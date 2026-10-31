# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""No message from a config check repeats a value read from the environment.

A config file may read ASH_* variables (`${NAME:default}`, or `!ENV`), and a
check resolves them as a scan does. Several validators quote the value they
refuse ("expiration must be a YYYY-MM-DD date, got '<value>'"), and an
`extends` error names the base it could not find, so a check hides each value
read from the environment before it prints those messages. The MCP
`validate_config` tool returns the same redacted messages to its client.

Each case below makes a check fail on a value taken from the environment, and
asserts the value appears nowhere in what the command or the tool returns.
"""

from __future__ import annotations

import json
import re
import sys
import textwrap
from pathlib import Path

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from automated_security_helper.cli.mcp_tools import mcp_validate_config

pytestmark = pytest.mark.unit

SECRET = "ghp_HIDDENSECRET4242"
VARIABLE = "ASH_TEST_HIDDEN_VALUE"

# (id, config text, extra files). Every case fails on the secret's value.
CASES = [
    pytest.param(
        f"project_name: demo\nglobal_settings:\n  suppressions:\n"
        f"    - rule_id: B101\n      path: a.py\n      reason: r\n"
        f"      expiration: ${{{VARIABLE}:2099-01-01}}\n",
        {},
        id="expiration-default-form",
    ),
    pytest.param(
        f"project_name: demo\nglobal_settings:\n  suppressions:\n"
        f"    - rule_id: B101\n      path: a.py\n      reason: r\n"
        f"      expiration: !ENV ${{{VARIABLE}:2099-01-01}}\n",
        {},
        id="expiration-env-tag",
    ),
    pytest.param(
        f"project_name: demo\ncontent_db_staleness_overrides:\n"
        f"  - database: !ENV ${{{VARIABLE}:grype-db}}\n"
        f"    policy: warn\n    expiration: '2099-01-01'\n    reason: r\n",
        {},
        id="content-database-name",
    ),
    pytest.param(
        f"extends: ${{{VARIABLE}:base.yaml}}\nproject_name: demo\n",
        {},
        id="extends-default-form",
    ),
    pytest.param(
        f"extends: !ENV ${{{VARIABLE}:base.yaml}}\nproject_name: demo\n",
        {},
        id="extends-env-tag",
    ),
    pytest.param(
        "extends: base.yaml\nproject_name: demo\n",
        {"base.yaml": f"extends: !ENV ${{{VARIABLE}:other.yaml}}\n"},
        id="extends-in-a-base",
    ),
]


@pytest.fixture
def project(tmp_path: Path, monkeypatch) -> Path:
    monkeypatch.setenv(VARIABLE, SECRET)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.chdir(tmp_path)
    return tmp_path


def _write(project: Path, text: str, extra: dict) -> Path:
    for name, body in extra.items():
        (project / name).write_text(body, encoding="utf-8")
    config = project / "ash.yaml"
    config.write_text(textwrap.dedent(text), encoding="utf-8")
    return config


COMMANDS = ["validate", "lint", "get", "validate-plugin-dependencies", "scan"]


def _run(project: Path, command: str, config: Path, monkeypatch, *extra: str):
    """Run `ash config <command>`, or `ash scan`, on ``config``."""
    if command == "scan":
        # Past config resolution the scan would run scanners; none may run.
        monkeypatch.setattr(
            "automated_security_helper.core.orchestrator.ASHScanOrchestrator.execute_scan",
            lambda *_a, **_k: (_ for _ in ()).throw(SystemExit(0)),
        )
        args = [
            "scan",
            "--mode",
            "local",
            "--no-progress",
            "--config",
            str(config),
            "--output-dir",
            str(project / "scan-output"),
        ]
    else:
        args = ["config", command, "--config", str(config)]
    return CliRunner().invoke(app, [*args, *extra])


@pytest.mark.parametrize("text, extra", CASES)
@pytest.mark.parametrize("command", COMMANDS)
def test_cli_output_hides_the_value(project, text, extra, command, monkeypatch):
    config = _write(project, text, extra)

    result = _run(project, command, config, monkeypatch)

    assert result.exit_code == 3, result.output
    assert SECRET not in result.output


# Values a message prints with repr() (`{v!r}`), which escapes a backslash and
# a non-printable character, and JSON escapes, the MCP result's encoding.
QUOTED_SECRETS = [
    pytest.param("SEK\\RITzq", id="backslash"),
    pytest.param("SEK\tRITzq", id="tab"),
    pytest.param("SEKR\u00cfT zq", id="non-ascii"),
]
SYMBOL_VARIABLE = "ASH_TEST_HIDDEN_SYMBOL"


def _forms(secret: str) -> set:
    return {
        secret,
        repr(secret)[1:-1],
        secret.encode("unicode_escape").decode("ascii"),
        json.dumps(secret)[1:-1],
    }


@pytest.mark.parametrize("secret", QUOTED_SECRETS)
@pytest.mark.parametrize("command", [*COMMANDS, "mcp-content", "mcp-path"])
def test_an_escaped_value_is_hidden_too(project, monkeypatch, secret, command):
    """A validator quotes the symbol it refuses with repr(); no form of it shows."""
    monkeypatch.setenv(SYMBOL_VARIABLE, secret)
    config = _write(
        project,
        "project_name: demo\nglobal_settings:\n  suppressions:\n"
        "    - rule_id: B101\n      path: a.py\n      reason: r\n"
        f"      symbol: ${{{SYMBOL_VARIABLE}:x}}\n",
        {},
    )

    if command.startswith("mcp-"):
        result = (
            mcp_validate_config(config_content=config.read_text())
            if command == "mcp-content"
            else mcp_validate_config(config_path=str(config))
        )
        assert result["valid"] is False, result
        # The strings the client receives, before any JSON encoding.
        output = "\n".join(e["message"] for e in result["errors"])
    else:
        run = _run(project, command, config, monkeypatch)
        assert run.exit_code == 3, run.output
        output = run.output

    for form in _forms(secret):
        assert form not in output, (form, output)


def test_a_base_named_from_the_environment_is_hidden_in_the_chain(project):
    """validate and lint print the files an extending config is built from."""
    (project / f"{SECRET}.yaml").write_text("project_name: demo\n", encoding="utf-8")
    config = _write(project, f"extends: ${{{VARIABLE}:base}}.yaml\n", {})
    runner = CliRunner()

    for command in ("validate", "lint"):
        result = runner.invoke(app, ["config", command, "--config", str(config)])

        assert result.exit_code == 0, result.output
        assert "Resolved source chain" in result.output, result.output
        assert SECRET not in result.output, result.output


def test_a_project_name_from_the_environment_is_hidden_by_vpd(project):
    (project / ".ashrc.yaml").write_text(
        f"project_name: ${{{VARIABLE}:demo}}\n", encoding="utf-8"
    )

    result = CliRunner().invoke(app, ["config", "validate-plugin-dependencies"])

    assert result.exit_code == 0, result.output
    assert "is valid" in result.output, result.output
    assert SECRET not in result.output, result.output


def test_fix_unused_lists_what_it_comments_out_without_the_value(project):
    from automated_security_helper.models.core import suppression_id

    config = project / ".ash" / ".ash.yaml"
    config.parent.mkdir()
    config.write_text(
        "project_name: demo\nglobal_settings:\n  suppressions:\n"
        f"    - path: ${{{VARIABLE}:src/a.py}}\n      rule_id: B101\n      reason: r\n",
        encoding="utf-8",
    )
    reports = project / ".ash" / "ash_output" / "reports"
    reports.mkdir(parents=True)
    unused = {"path": SECRET, "rule_id": "B101", "reason": "r"}
    assert suppression_id(unused)
    (reports / "ash.unused-suppressions.json").write_text(
        json.dumps({"unused_suppressions": [unused]}), encoding="utf-8"
    )

    result = CliRunner().invoke(
        app, ["config", "lint", "--config", str(config), "--fix-unused", "-y"]
    )

    assert result.exit_code == 0, result.output
    assert "Commented out" in result.output, result.output
    assert SECRET not in result.output, result.output


def test_values_are_paired_by_key_not_position(monkeypatch):
    """An interpolated key that equals another key shifts every later position.

    Both variables are set, as they were for the run: a reference whose
    variable is unset gave its default, the file's own text, and is not paired.
    """
    from automated_security_helper.config.config_validator import (
        _interpolated_pairs,
    )

    monkeypatch.setenv("ASH_K", "b")
    monkeypatch.setenv("ASH_S", "SECRETVALUE")
    literal = {"${ASH_K:b}": "1", "b": "2", "c": "${ASH_S:z}"}
    resolved = {"b": "2", "c": "SECRETVALUE"}

    assert ("SECRETVALUE", "${ASH_S:z}") in _interpolated_pairs(literal, resolved)


def test_a_short_value_is_not_redacted(project, monkeypatch):
    """Redacting a one-letter value would cut every word it appears in."""
    monkeypatch.setenv("ASH_TEST_ONE", "a")
    config = _write(project, "project_name: ${ASH_TEST_ONE:x}\nfoo_unknown: 1\n", {})

    result = CliRunner().invoke(app, ["config", "validate", "--config", str(config)])

    assert result.exit_code == 0, result.output
    assert "Unknown top-level field 'foo_unknown' - a scan ignores it" in result.output
    assert "<value>" not in result.output, result.output


@pytest.mark.parametrize("text, extra", CASES)
@pytest.mark.parametrize("given_as", ["content", "path"])
def test_mcp_validate_config_hides_the_value(project, text, extra, given_as):
    config = _write(project, text, extra)

    if given_as == "content":
        result = mcp_validate_config(config_content=config.read_text())
    else:
        result = mcp_validate_config(config_path=str(config))

    assert result["valid"] is False, result
    assert SECRET not in json.dumps(result)


def test_a_value_the_file_holds_is_not_quoted_either(project):
    """Nothing quotes an input value, whatever its source."""
    config = _write(
        project,
        "project_name: demo\nglobal_settings:\n  suppressions:\n"
        "    - rule_id: B101\n      path: a.py\n      reason: r\n"
        "      expiration: not-a-date-literal\n",
        {},
    )

    result = CliRunner().invoke(app, ["config", "validate", "--config", str(config)])

    assert result.exit_code == 3, result.output
    assert "not-a-date-literal" not in result.output
    assert "global_settings.suppressions[0].expiration" in result.output


def test_a_warning_hides_the_value_too(project):
    """A check a scan accepts quotes the path it warns about; not one from the environment."""
    (project / SECRET).mkdir()
    config = _write(
        project,
        "project_name: demo\nglobal_settings:\n  ignore_paths:\n"
        f"    - path: ${{{VARIABLE}:vendor}}\n      reason: r\n",
        {},
    )
    runner = CliRunner()

    validate = runner.invoke(app, ["config", "validate", "--config", str(config)])
    lint = runner.invoke(app, ["config", "lint", "--config", str(config)])
    mcp = mcp_validate_config(config_path=str(config))

    assert validate.exit_code == 0, validate.output
    assert "points to a directory" in validate.output, validate.output
    assert "points to a directory" in lint.output, lint.output
    for output in (validate.output, lint.output, json.dumps(mcp)):
        assert SECRET not in output


#: How an extends error names a base an entry named through the environment, and
#: the path it resolved to: each is `<value>` at its place (config_sources), and
#: the reason is the one the chain failed for.
MISSING_BASE_BY_PLACE = (
    "'extends: <value>' in",
    "names <value>, which does not exist or is not a file",
)


def _flat(output: str) -> str:
    return " ".join(re.sub(r"\x1b\[[0-9;]*m", "", output).split())


def _assert_names_the_missing_base_by_place(text: str) -> None:
    flat = _flat(text)
    for part in MISSING_BASE_BY_PLACE:
        assert part in flat, flat


@pytest.mark.parametrize("command", ["validate", "lint", "scan"])
def test_a_reference_that_names_a_missing_base_is_named_by_place(
    project, monkeypatch, command
):
    """The entry and the path it names are `<value>`, and the reason is the
    chain's own: the scan and both checks give the same one, and none says the
    reference was never resolved."""
    config = _write(project, f"extends: ${{{VARIABLE}:base.yaml}}\n", {})

    run = _run(project, command, config, monkeypatch)

    assert run.exit_code == 3, run.output
    flat = _flat(run.output)
    _assert_names_the_missing_base_by_place(flat)
    assert "${" not in flat, flat
    assert SECRET not in run.output


@pytest.mark.parametrize("command", ["validate", "lint", "scan"])
def test_a_chain_that_resolves_only_without_the_environment_is_named_by_place(
    project, monkeypatch, command
):
    """A file literally named `${VAR:base.yaml}` exists, the value VAR holds does not."""
    reference = f"${{{VARIABLE}:base.yaml}}"
    (project / reference).write_text("project_name: demo\n", encoding="utf-8")
    config = _write(project, f"extends: {reference}\n", {})

    run = _run(project, command, config, monkeypatch)

    assert run.exit_code == 3, run.output
    _assert_names_the_missing_base_by_place(run.output)
    assert SECRET not in run.output


def test_lint_fix_refuses_a_file_with_references_when_there_is_a_fix(project):
    """--fix would write the values the references hold; it changes nothing."""
    config = _write(
        project,
        f"project_name: ${{{VARIABLE}:demo}}\nbuild:\n  build_mode: ONLINE\n",
        {},
    )
    before = config.read_bytes()

    result = CliRunner().invoke(
        app, ["config", "lint", "--config", str(config), "--fix", "-y"]
    )

    assert result.exit_code == 1, result.output
    assert "make these fixes by hand" in result.output, result.output
    assert config.read_bytes() == before
    assert SECRET not in result.output


def test_a_warning_from_a_base_hides_the_value_too(project):
    """The values a base reads from the environment are redacted as the root's are."""
    (project / SECRET).mkdir()
    config = _write(
        project,
        "extends: base.yaml\nproject_name: demo\n",
        {
            "base.yaml": "global_settings:\n  ignore_paths:\n"
            f"    - path: ${{{VARIABLE}:vendor}}\n      reason: r\n"
        },
    )
    runner = CliRunner()

    validate = runner.invoke(app, ["config", "validate", "--config", str(config)])
    lint = runner.invoke(app, ["config", "lint", "--config", str(config)])
    mcp = mcp_validate_config(config_path=str(config))

    assert validate.exit_code == 0, validate.output
    assert "points to a directory" in validate.output, validate.output
    assert "points to a directory" in lint.output, lint.output
    # A warning, as validate's exit 0 says: validate_config lists warnings apart
    # from its errors (bc242f65e).
    assert mcp["valid"] is True, mcp
    assert any("points to a directory" in w["message"] for w in mcp["warnings"]), mcp
    for output in (validate.output, lint.output, json.dumps(mcp)):
        assert SECRET not in output, output


def test_an_operator_config_extends_error_hides_the_value(project, monkeypatch):
    """The operator's own config (workspace mode's trusted base) is resolved too."""
    from automated_security_helper.config.resolve_config import resolve_config
    from automated_security_helper.core.exceptions import ASHConfigValidationError

    monkeypatch.setenv("ASH_TEST_OPBASE", "SECRETOPZQ.yaml")
    repo = project / "repo"
    repo.mkdir()
    (repo / ".ashrc.yaml").write_text("project_name: demo\n", encoding="utf-8")
    operator = project / "operator" / "ash.yaml"
    operator.parent.mkdir()
    operator.write_text(
        "extends: ${ASH_TEST_OPBASE:base.yaml}\nproject_name: op\n",
        encoding="utf-8",
    )

    with pytest.raises(ASHConfigValidationError) as raised:
        resolve_config(
            source_dir=repo, fallback_to_default=False, trusted_config_path=operator
        )

    assert "SECRETOPZQ" not in str(raised.value), raised.value
    _assert_names_the_missing_base_by_place(str(raised.value))


def test_the_error_does_not_blame_a_base_that_exists(project, monkeypatch):
    """The env-named base exists; a file it extends does not. The error names
    that file's entry, and the base and the path, both chosen by the
    environment, by place."""
    from automated_security_helper.config.config_validator import ConfigValidator
    from automated_security_helper.config.resolve_config import resolve_config
    from automated_security_helper.core.exceptions import ASHConfigValidationError

    monkeypatch.setenv("ASH_TEST_HIDDEN_BASE", "real-base.yaml")
    config = _write(
        project,
        "extends: ${ASH_TEST_HIDDEN_BASE:a.yaml}\nproject_name: demo\n",
        {"real-base.yaml": "extends: missing-literal.yaml\n"},
    )

    (error,) = ConfigValidator.check_config_file(config).errors
    with pytest.raises(ASHConfigValidationError) as raised:
        resolve_config(config, fallback_to_default=False)

    for reason in (error, str(raised.value)):
        flat = " ".join(reason.split())
        assert (
            "'extends: missing-literal.yaml' in <value> names <value>, which does "
            "not exist or is not a file" in flat
        ), flat
        assert "real-base" not in flat, flat


def test_a_base_the_environment_named_that_does_not_parse_is_named_by_place(
    project, monkeypatch
):
    """The reader's own refusal of a base names the base's path, which here the
    environment chose: it is given without its text."""
    from automated_security_helper.config.config_sources import (
        resolve_config_document,
    )
    from automated_security_helper.core.exceptions import ASHConfigSourceError

    monkeypatch.setenv(VARIABLE, f"{SECRET}.toml")
    (project / f"{SECRET}.toml").write_text("not = [valid\n", encoding="utf-8")
    config = _write(
        project, f"extends: ${{{VARIABLE}:base.yaml}}\nproject_name: demo\n", {}
    )

    with pytest.raises(ASHConfigSourceError) as raised:
        resolve_config_document(config, confine_to=project)

    text = str(raised.value)
    assert SECRET not in text, text
    assert "Base config <value>, extended by" in text, text


def test_a_failed_patch_operation_does_not_quote_a_value_read_from_the_environment(
    project,
):
    """A refused patch operation is quoted in its error, and its value here was
    read from the environment: the error is given without the environment."""
    from automated_security_helper.config.config_sources import (
        resolve_config_document,
    )
    from automated_security_helper.core.exceptions import ASHConfigSourceError

    config = _write(
        project,
        "project_name: demo\npatch:\n"
        f"  - op: add\n    path: /no/such/parent\n    value: ${{{VARIABLE}:x}}\n",
        {},
    )

    with pytest.raises(ASHConfigSourceError) as raised:
        resolve_config_document(config, confine_to=project)

    assert SECRET not in str(raised.value), raised.value


@pytest.mark.parametrize(
    "path, shown",
    [
        ("/no/such/parent", "'/no/such/parent'"),
        (f"${{{VARIABLE}:/x}}", "'<value>'"),
    ],
    ids=["path-written", "path-read"],
)
def test_a_failed_patch_operation_is_named_by_its_entry_op_and_path(
    project, path, shown
):
    """The error says which operation failed, by its entry, its op and its
    path, the path by its place (one read from the environment is `<value>`),
    and why, without the value it writes or the text jsonpatch gives, which
    quotes the document."""
    from automated_security_helper.config.config_sources import (
        resolve_config_document,
    )
    from automated_security_helper.core.exceptions import ASHConfigSourceError

    config = _write(
        project,
        "project_name: demo\npatch:\n"
        f"  - op: add\n    path: {path}\n    value: ${{{VARIABLE}:x}}\n",
        {},
    )

    with pytest.raises(ASHConfigSourceError) as raised:
        resolve_config_document(config, confine_to=project)

    text = " ".join(str(raised.value).split())
    assert SECRET not in text, text
    assert "'patch' entry 0 in" in text, text
    assert f"(add at {shown}) failed:" in text, text
    assert "the path does not fit the document it patches" in text, text


def test_redaction_does_not_redact_its_own_marker():
    """One value replaced by `<value>`, then another value matching inside it."""
    from automated_security_helper.config.config_validator import redact_values

    redacted = redact_values("Input should be a valid value", ["should", "value"])

    assert redacted == "Input <value> be a valid <value>"


def test_a_model_error_does_not_redact_inside_its_own_marker(project):
    """The input's values "should" and "value" are redacted from pydantic's
    message; replacing them one after the other printed `<<value>>`."""
    config = _write(
        project,
        "project_name: demo\nglobal_settings:\n  suppressions: {x: should, y: value}\n",
        {},
    )

    result = CliRunner().invoke(app, ["config", "validate", "--config", str(config)])

    assert result.exit_code == 3, result.output
    flat = " ".join(result.output.split())
    assert "global_settings.suppressions" in flat, flat
    assert "<<" not in flat and ">>" not in flat, flat


def test_a_name_the_schema_defines_is_not_redacted_from_a_message():
    """A section whose `name` equals its key ("bandit") had the key redacted
    from a validator's message that names the path: "scanners.<value>.
    severity_threshold is not a section-level key". A schema name (a field,
    an alias, a model's name, a declared plugin key) is not a value to hide;
    the input's other values still are."""
    from automated_security_helper.config.config_validator import ConfigValidator

    error = {
        "type": "value_error",
        "loc": ("scanners", "bandit"),
        "msg": "Value error, scanners.bandit.severity_threshold is not a "
        "section-level key; move severity_threshold under options (got "
        "'SECRETVALUEZQ' for cdk-nag)",
        "input": {
            "name": "bandit",
            "enabled": True,
            "severity_threshold": "SECRETVALUEZQ",
            "other": "cdk-nag",
        },
    }

    message = ConfigValidator.format_model_error(error)

    assert "Invalid value at 'scanners.bandit'" in message, message
    assert "scanners.bandit.severity_threshold is not a section-level key" in message
    assert "for cdk-nag" in message, message
    assert "SECRETVALUEZQ" not in message, message
    assert "got '<value>'" in message, message


def test_keys_of_four_characters_or_more_stay_readable(project):
    """The input's keys are not redacted from its error, whatever their length."""
    config = _write(
        project,
        "project_name: demo\nglobal_settings:\n  suppressions: {should: 1, valid: 2}\n",
        {},
    )

    result = CliRunner().invoke(app, ["config", "validate", "--config", str(config)])

    assert result.exit_code == 3, result.output
    assert "Input should be a valid list" in " ".join(result.output.split())


PROBE = "ASH_TEST_PROBE"
PROBE_VALUE = "SECRETDIRZQ"

# A key the file reads from the environment, which the model refuses.
KEY_CASES = [
    pytest.param(
        f"project_name: demo\nglobal_settings:\n  ${{{PROBE}:k}}: 1\n", {}, id="root"
    ),
    pytest.param(
        "extends: base.yaml\nproject_name: demo\n",
        {"base.yaml": f"global_settings:\n  ${{{PROBE}:k}}: 1\n"},
        id="base",
    ),
]


@pytest.mark.parametrize("text, extra", KEY_CASES)
@pytest.mark.parametrize("where", ["named", "discovered", "operator"])
def test_the_scan_hides_a_key_read_from_the_environment(
    project, monkeypatch, caplog, text, extra, where
):
    """The scan's refusal, and the ERROR line it logs, do not name the key read
    from the environment. The operator's config (workspace mode's trusted base)
    is refused the same way."""
    from automated_security_helper.config.resolve_config import resolve_config
    from automated_security_helper.core.exceptions import ASHConfigValidationError

    monkeypatch.setenv(PROBE, PROBE_VALUE)
    if where == "operator":
        operator_dir = project / "operator"
        operator_dir.mkdir()
        operator = _write(operator_dir, text, extra)
        repo = project / "repo"
        repo.mkdir()
        (repo / ".ashrc.yaml").write_text("project_name: demo\n", encoding="utf-8")
        kwargs = {"source_dir": repo, "trusted_config_path": operator}
    else:
        config = _write(project, text, extra)
        kwargs = (
            {"source_dir": project}
            if where == "discovered"
            else {"config_path": config}
        )

    with caplog.at_level("DEBUG"):
        with pytest.raises(ASHConfigValidationError) as raised:
            resolve_config(fallback_to_default=False, **kwargs)

    assert "Extra inputs are not permitted" in str(raised.value), raised.value
    assert PROBE_VALUE not in str(raised.value), raised.value
    assert PROBE_VALUE not in caplog.text, caplog.text


@pytest.mark.parametrize("text, extra", KEY_CASES)
@pytest.mark.parametrize("command", ["get", "validate-plugin-dependencies", "scan"])
def test_commands_that_load_the_config_hide_a_key_read_from_the_environment(
    project, monkeypatch, text, extra, command
):
    monkeypatch.setenv(PROBE, PROBE_VALUE)
    config = _write(project, text, extra)

    result = _run(project, command, config, monkeypatch)

    assert result.exit_code == 3, result.output
    assert PROBE_VALUE not in result.output, result.output


def _workspace(project: Path, project_config: str) -> list:
    """A one-project workspace; the project's config is ``project_config``."""
    (project / "team.code-workspace").write_text(
        json.dumps({"folders": [{"path": "svc"}]}), encoding="utf-8"
    )
    (project / "svc" / ".ash").mkdir(parents=True)
    (project / "svc" / ".ash" / ".ash.yaml").write_text(
        textwrap.dedent(project_config), encoding="utf-8"
    )
    return ["scan", "--no-progress", "--workspace", "team.code-workspace"]


def _stub_scan(monkeypatch):
    monkeypatch.setattr(
        "automated_security_helper.core.orchestrator.ASHScanOrchestrator.execute_scan",
        lambda *_a, **_k: (_ for _ in ()).throw(SystemExit(0)),
    )


def test_a_workspace_scan_hides_a_key_read_from_the_environment(
    project, monkeypatch, caplog
):
    monkeypatch.setenv(PROBE, PROBE_VALUE)
    _stub_scan(monkeypatch)
    args = _workspace(
        project, f"project_name: svc\nglobal_settings:\n  ${{{PROBE}:k}}: 1\n"
    )

    with caplog.at_level("DEBUG"):
        result = CliRunner().invoke(app, args)

    assert result.exit_code != 0, result.output
    assert "Extra inputs are not permitted" in " ".join(result.output.split())
    assert PROBE_VALUE not in result.output, result.output
    assert PROBE_VALUE not in caplog.text, caplog.text


OPERATOR_SECRET = "SECRETOPZQ.yaml"


def _operator_config(project: Path, monkeypatch) -> Path:
    """ASH_CONFIG names a file whose base is named by an environment variable."""
    monkeypatch.setenv("ASH_TEST_OPBASE", OPERATOR_SECRET)
    operator = project / "operator" / "ash.yaml"
    operator.parent.mkdir()
    operator.write_text(
        "extends: ${ASH_TEST_OPBASE:base.yaml}\nproject_name: op\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("ASH_CONFIG", str(operator))
    return operator


def test_an_ash_config_file_chain_error_is_hidden_from_resolve_config(
    project, monkeypatch, caplog
):
    from automated_security_helper.config.resolve_config import resolve_config
    from automated_security_helper.core.exceptions import ASHConfigValidationError

    _operator_config(project, monkeypatch)
    repo = project / "repo"
    repo.mkdir()

    with caplog.at_level("DEBUG"):
        with pytest.raises(ASHConfigValidationError) as raised:
            resolve_config(source_dir=repo)

    _assert_names_the_missing_base_by_place(str(raised.value))
    assert "SECRETOPZQ" not in str(raised.value), raised.value
    assert "SECRETOPZQ" not in caplog.text, caplog.text


@pytest.mark.parametrize(
    "mode", ["scan", "workspace", "workspace-config"], ids=lambda m: m
)
def test_an_ash_config_file_chain_error_is_hidden_from_the_scan(
    project, monkeypatch, caplog, mode
):
    """`ash scan` with ASH_CONFIG, a workspace scan, and a workspace scan given
    the same file with --config: each refuses the file (exit 3)."""
    operator = _operator_config(project, monkeypatch)
    _stub_scan(monkeypatch)
    if mode == "scan":
        args = ["scan", "--mode", "local", "--no-progress", "--output-dir", "out"]
    else:
        args = _workspace(project, "project_name: svc\n")
        if mode == "workspace-config":
            args += ["--config", str(operator)]

    with caplog.at_level("DEBUG"):
        result = CliRunner().invoke(app, args)

    assert result.exit_code == 3, result.output
    _assert_names_the_missing_base_by_place(result.output)
    assert "SECRETOPZQ" not in result.output, result.output
    assert "SECRETOPZQ" not in caplog.text, caplog.text


def test_the_workspace_settings_refusal_hides_the_value(project, monkeypatch, caplog):
    """A workspace scan given a config file with --config, and no ASH_CONFIG,
    reads its execution settings from that file (_load_with_confinement) and
    refuses it when it cannot be loaded: the refusal quotes the chain's error,
    with the value read from the environment by its place."""
    from automated_security_helper.core.exceptions import ASHConfigValidationError
    from automated_security_helper.interactions.run_ash_scan import (
        ScanOptions,
        _resolve_workspace_execution_config,
    )

    operator = _operator_config(project, monkeypatch)
    monkeypatch.delenv("ASH_CONFIG")

    with caplog.at_level("DEBUG"), pytest.raises(ASHConfigValidationError) as refused:
        _resolve_workspace_execution_config(
            ScanOptions(
                source_dir=project, output_dir=project / "out", config=str(operator)
            )
        )

    _assert_names_the_missing_base_by_place(str(refused.value))
    assert "SECRETOPZQ" not in str(refused.value), str(refused.value)
    assert "SECRETOPZQ" not in caplog.text, caplog.text


@pytest.mark.parametrize("command", ["resolve_config", "scan"])
def test_an_ash_config_file_model_error_is_hidden(
    project, monkeypatch, caplog, command
):
    """The model's refusal of the ASH_CONFIG file shows neither pydantic's
    `input_value='<value>'` text nor the key in the error's location."""
    from automated_security_helper.config.resolve_config import resolve_config
    from automated_security_helper.core.exceptions import ASHConfigValidationError

    monkeypatch.setenv("ASH_TEST_OPBASE", "SECRETOPZQ")
    monkeypatch.setenv(PROBE, PROBE_VALUE)
    operator = project / "operator" / "ash.yaml"
    operator.parent.mkdir()
    operator.write_text(
        "project_name: op\nfail_on_findings: ${ASH_TEST_OPBASE:true}\n"
        f"global_settings:\n  ${{{PROBE}:k}}: 1\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("ASH_CONFIG", str(operator))
    (project / "repo").mkdir()

    with caplog.at_level("DEBUG"):
        if command == "resolve_config":
            with pytest.raises(ASHConfigValidationError) as raised:
                resolve_config(source_dir=project / "repo")
            output = str(raised.value)
        else:
            _stub_scan(monkeypatch)
            result = CliRunner().invoke(
                app,
                ["scan", "--mode", "local", "--no-progress", "--source-dir", "repo"],
            )
            assert result.exit_code == 3, result.output
            output = result.output

    flat = " ".join(output.split())
    assert "Invalid value at 'fail_on_findings'" in flat, flat
    for secret in ("SECRETOPZQ", PROBE_VALUE):
        assert secret not in output, output
        assert secret not in caplog.text, caplog.text
    assert "input_value" not in output, output


@pytest.mark.parametrize("where", ["root", "base"])
def test_a_value_printed_without_its_trailing_slashes_is_hidden_too(project, where):
    """An ignore path read from the environment, ending in "/", is printed nowhere.

    A trailing "/" is read as the directory and everything under it, so there
    is no directory warning to print the path; the checks accept the file. The
    redaction of the path without its slashes, which such a warning needs, is
    pinned on its own below (test_printed_forms_drop_a_value_s_trailing_slashes).
    """
    (project / PROBE_VALUE).mkdir()
    entry = (
        "global_settings:\n  ignore_paths:\n"
        f"    - path: ${{{PROBE}:vendor}}//\n      reason: r\n"
    )
    if where == "root":
        config = _write(project, "project_name: demo\n" + entry, {})
    else:
        config = _write(
            project, "extends: base.yaml\nproject_name: demo\n", {"base.yaml": entry}
        )
    runner = CliRunner()

    with pytest.MonkeyPatch.context() as mp:
        mp.setenv(PROBE, PROBE_VALUE)
        validate = runner.invoke(app, ["config", "validate", "--config", str(config)])
        lint = runner.invoke(app, ["config", "lint", "--config", str(config)])
        mcp = mcp_validate_config(config_path=str(config))

    assert validate.exit_code == 0, validate.output
    assert lint.exit_code == 0, lint.output
    assert mcp["valid"] is True, mcp
    for output in (validate.output, lint.output, json.dumps(mcp)):
        assert PROBE_VALUE not in output, output


def test_a_value_equal_to_the_marker_word_is_not_redacted_twice(project, monkeypatch):
    """With the value "value", the model's own redaction and the check's
    stacked: "<<value>>" from validate, "<<<value>>>" from lint.

    A field's message names the value by its place, so no text search for it
    runs over the message any more, and the word "value" in the message's own
    text ("Invalid value at") stays as it is."""
    monkeypatch.setenv(PROBE, "value")
    config = _write(
        project,
        "project_name: demo\nglobal_settings:\n  suppressions:\n"
        "    - rule_id: B101\n      path: a.py\n      reason: r\n"
        f"      expiration: ${{{PROBE}:x}}\n",
        {},
    )
    runner = CliRunner()

    validate = runner.invoke(app, ["config", "validate", "--config", str(config)])
    lint = runner.invoke(app, ["config", "lint", "--config", str(config)])

    for result in (validate, lint):
        assert result.exit_code == 3, result.output
        assert (
            "Invalid value at 'global_settings.suppressions[0].expiration'"
            in result.output
        ), result.output
        assert "<<" not in result.output, result.output


def test_redaction_is_idempotent():
    from automated_security_helper.config.config_validator import redact_values

    text = "Invalid <value> at 'x': <value>"

    assert redact_values(text, ["value"]) == text


def test_overlapping_values_are_redacted_as_one_span():
    """Neither value's remainder is left: "<value>/baz-long" and "foo/<value>"
    each print part of one of them."""
    from automated_security_helper.config.config_validator import redact_values

    redacted = redact_values("at foo/bar/baz-long now", ["foo/bar", "bar/baz-long"])

    assert redacted == "at <value> now"


def test_an_operator_config_refusal_names_the_source_dir(project):
    """The operator config's refusal suggests lint with the scan's source dir."""
    from automated_security_helper.config.resolve_config import (
        lint_hint,
        resolve_config,
    )
    from automated_security_helper.core.exceptions import ASHConfigValidationError

    repo = project / "repo"
    repo.mkdir()
    (repo / ".ashrc.yaml").write_text("project_name: demo\n", encoding="utf-8")
    operator = project / "operator" / "ash.yaml"
    operator.parent.mkdir()
    operator.write_text(
        "project_name: op\nfail_on_findings: sometimes\n", encoding="utf-8"
    )

    with pytest.raises(ASHConfigValidationError) as raised:
        resolve_config(
            source_dir=repo, fallback_to_default=False, trusted_config_path=operator
        )

    assert str(raised.value).endswith(lint_hint(operator, repo)), raised.value
    assert lint_hint(operator, repo) != lint_hint(operator)


@pytest.mark.skipif(
    sys.platform == "win32", reason="the working directory cannot be removed on Windows"
)
def test_lint_hint_with_a_deleted_working_directory_keeps_the_source_dir(
    tmp_path, monkeypatch
):
    """The working directory is deleted while the process runs, so there is no
    directory for source_dir to equal: the hint keeps --source-dir instead of
    raising out of the refusal it decorates."""
    import os

    from automated_security_helper.config.resolve_config import lint_hint

    config = tmp_path / "ash.yaml"
    config.write_text("project_name: demo\n", encoding="utf-8")
    source = tmp_path / "repo"
    source.mkdir()
    launched = tmp_path / "launched-here"
    launched.mkdir()
    monkeypatch.chdir(launched)
    os.rmdir(launched)

    hint = lint_hint(config, source)

    assert hint.startswith("Run: ash config lint --config "), hint
    assert hint.endswith(f" --source-dir {source.as_posix()}"), hint


def test_touching_values_are_redacted_as_one_span():
    """Two values next to each other are one run: "<value><value>" would say
    there are two of them, and where one ends."""
    from automated_security_helper.config.config_validator import redact_values

    redacted = redact_values("at /aaaa/bbbb now", ["/aaaa", "/bbbb"])

    assert redacted == "at <value> now"


@pytest.mark.parametrize("rest", ["/./base.yaml", "//base.yaml", "/x/../base.yaml"])
@pytest.mark.parametrize(
    "args",
    [
        pytest.param(["validate"], id="validate"),
        pytest.param(["lint"], id="lint"),
        pytest.param(["lint", "--fix", "-y"], id="lint-fix"),
        pytest.param(["lint", "--fix-unused", "-y"], id="lint-fix-unused"),
    ],
)
def test_a_base_named_from_the_environment_is_hidden_after_normalization(
    project, monkeypatch, rest, args
):
    """The chain prints each base's normalized path, which is not the string the
    reference resolved to ("SECRETDIRZQ/./base.yaml"); the normalized form is
    redacted, and the part the reference itself resolved to as well."""
    monkeypatch.setenv(PROBE, PROBE_VALUE)
    (project / PROBE_VALUE / "x").mkdir(parents=True)
    (project / PROBE_VALUE / "base.yaml").write_text(
        "project_name: demo\n", encoding="utf-8"
    )
    config = _write(project, f"extends: ${{{PROBE}:x}}{rest}\n", {})

    result = CliRunner().invoke(
        app, ["config", args[0], "--config", str(config), *args[1:]]
    )

    assert PROBE_VALUE not in result.output, result.output
    if args == ["validate"]:
        assert result.exit_code == 0, result.output
        assert "Resolved source chain" in result.output, result.output


@pytest.mark.parametrize(
    "ignore_path, suggestion",
    [(True, "Use '<value>/'"), (False, "Use '<value>/**/*'")],
)
def test_a_value_ending_in_a_slash_keeps_the_slash_in_the_suggestion(
    ignore_path, suggestion
):
    """The directory warning suggests `<path without its "/">/` (or `/**/*`);
    the value with its slash would take that slash into the marker.

    Checked on the warning's own wording: a path written with a trailing "/"
    is read as the directory and gets no warning, so no config reaches this
    text with a value that ends in "/".
    """
    from automated_security_helper.config.config_validator import (
        directory_path_advice,
        redact_values,
    )

    warning = directory_path_advice(PROBE_VALUE, ignore_path=ignore_path)

    shown = redact_values(warning, [PROBE_VALUE + "/"])

    assert suggestion in shown, shown
    assert PROBE_VALUE not in shown, shown


@pytest.mark.parametrize("slashes", ["/", "//"])
def test_printed_forms_drop_a_value_s_trailing_slashes(slashes):
    """A value ending in "/" is matched without the slashes, so a message that
    prints the path without them hides it as well as one that prints them."""
    from automated_security_helper.config.config_validator import (
        _printed_forms,
        redact_values,
    )

    assert _printed_forms(PROBE_VALUE + slashes) == _printed_forms(PROBE_VALUE)
    for text in (f"'{PROBE_VALUE}'", f"'{PROBE_VALUE}{slashes}'"):
        assert PROBE_VALUE not in redact_values(text, [PROBE_VALUE + slashes])


@pytest.mark.parametrize("sep", ["\r\n", "\r"], ids=["crlf", "lone-cr"])
def test_printed_forms_cover_a_text_mode_pipes_newline_rewrite(sep):
    """A child read in text mode hands back the value with LF where the value
    itself holds CR or CRLF (universal newlines), so the forms carry the
    LF-normalized spelling and its own escapes with the value's own."""
    from automated_security_helper.config.config_validator import (
        _printed_forms,
        redact_values,
    )

    value = f"/nonexistent/ENVCANARY-nl{sep}77aa/settings.yaml"
    normalized = value.replace("\r\n", "\n").replace("\r", "\n")

    forms = _printed_forms(value)
    assert value in forms, forms
    assert normalized in forms, forms
    assert normalized.encode("unicode_escape").decode("ascii") in forms, forms
    for text in (f"tool read {value} twice", f"tool read {normalized} twice"):
        assert "ENVCANARY" not in redact_values(text, [value])


@pytest.mark.parametrize(
    "code",
    [
        pytest.param("\x1b[1m", id="sgr"),
        pytest.param("\x1b[K", id="csi-erase"),
        pytest.param("\x1b]8;;https://h.example\x1b\\", id="osc-link"),
    ],
)
def test_printed_forms_cover_a_values_own_escape_code_stripped(code):
    """The shown layers strip every complete CSI or OSC sequence from a
    tool's text before matching, so a value that itself holds such a code
    appears there in its stripped spelling, and the forms carry it."""
    from automated_security_helper.config.config_validator import (
        _printed_forms,
        redact_values,
    )

    value = f"/nonexistent/ENVCANARY-esc{code}77aa/settings.yaml"
    stripped = value.replace(code, "")

    forms = _printed_forms(value)
    assert value in forms, forms
    assert stripped in forms, forms
    for text in (f"tool read {value} twice", f"tool read {stripped} twice"):
        assert "ENVCANARY" not in redact_values(text, [value])


@pytest.mark.parametrize(
    "surrogate",
    [
        pytest.param(0xDCE9, id="an-undecodable-byte"),
        pytest.param(0xD800, id="a-lone-high-surrogate"),
    ],
)
def test_a_value_with_no_utf_8_spelling_is_still_hidden(surrogate):
    """A value read from a name that is not UTF-8 holds a lone surrogate. It
    has no URL spelling: quote() encodes UTF-8 strictly, as a library that
    formats it into a URL does, so no message prints one. Its other forms
    still hide it, and redacting with it never raises."""
    from automated_security_helper.config.config_validator import (
        REDACTED,
        _printed_forms,
        redact_values,
    )

    value = "/nonexistent/ENVCANARY-surr/secr" + chr(surrogate) + "t.key"

    forms = _printed_forms(value)
    assert value in forms, forms
    assert repr(value)[1:-1] in forms, forms
    shown = redact_values(f"cannot read '{value}' or {value!r}", [value])
    assert "ENVCANARY" not in shown, shown
    assert REDACTED in shown, shown


@pytest.mark.parametrize(
    "value",
    [
        pytest.param(r".*\.ENVCANARY-bslash\.min\.js$", id="regex"),
        pytest.param("C:\\Users\\ENVCANARY-bslash\\key.pem", id="windows-path"),
    ],
)
def test_a_backslash_value_is_hidden_in_a_formatted_structure(value):
    """Formatting a dict writes each string by repr(), which doubles every
    backslash, so the literal value is not in the text; the escaped spelling
    (_printed_forms) is what has to match."""
    from automated_security_helper.config.config_validator import (
        REDACTED,
        redact_values,
    )

    dumped = f"Settings: {{'pattern': {[value]!r}}}"
    # The control: the escaped spelling is there and would leak as it is,
    # while the value's own spelling is not.
    assert value not in dumped, dumped
    assert "ENVCANARY-bslash" in dumped, dumped

    redacted = redact_values(dumped, [value])
    assert "ENVCANARY" not in redacted, redacted
    assert REDACTED in redacted, redacted


def test_a_value_with_a_quote_is_hidden_in_an_escaping_repr():
    """repr() of a text that holds both quote kinds picks single quotes and
    escapes the single quote, so a value holding one prints as its
    backslash-escaped rendering. That rendering is a printed form of the
    value and is hidden, as the JSON escaping of a double quote already is."""
    from automated_security_helper.config.config_validator import (
        REDACTED,
        redact_values,
    )

    value = "pa'ss-wekvanmo"
    attribute = 'say "hi" ' + value
    text = f"attribute {attribute!r} refused"
    # The control: the escaped rendering is in the text and would leak as it
    # is, while the value's own spelling is not.
    assert value not in text, text
    assert "pa\\'ss-wekvanmo" in text, text

    redacted = redact_values(text, [value])
    assert "wekvanmo" not in redacted, redacted
    assert REDACTED in redacted, redacted

    quoted = 'qz"34vb-f21x'
    dumped = f"message {{'got': {json.dumps(['say ' + quoted])}}} refused"
    assert quoted not in dumped, dumped
    cleaned = redact_values(dumped, [quoted])
    assert "34vb-f21x" not in cleaned, cleaned


def test_an_environment_word_glued_by_underscores_stays_in_a_report_path():
    """On a CI-like host the environment holds common words (USER=runner,
    RUNNER_OS=Linux, GITHUB_BASE_REF=main). Under the TEST-REPORT word rule
    (_redact_for_test_reports, which only the report backstop calls) "_" is a
    word character, so a test path or module name that happens to contain
    such a word between underscores is printed intact -- not mangled into
    markers that hide no secret. The same words standing alone are still
    replaced."""
    from automated_security_helper.config.config_validator import (
        REDACTED,
        _redact_for_test_reports,
    )

    values = ["runner", "Linux", "main"]
    text = "test_uv_tool_runner.py:74: the test_uv_tool_runner module raised"
    assert _redact_for_test_reports(text, values) == text

    standalone = _redact_for_test_reports("the user runner chose main on Linux", values)
    assert standalone == f"the user {REDACTED} chose {REDACTED} on {REDACTED}", (
        standalone
    )


def test_a_product_message_hides_a_short_value_glued_by_underscores():
    """The product's own messages keep the strict word rule: "_" bounds a
    word like any other non-alphanumeric character, so a value glued to a
    word with "_" is hidden there, standing alone, and quoted alike."""
    from automated_security_helper.config.config_validator import (
        REDACTED,
        redact_values,
    )

    glued = redact_values("the key x_hidden7_y is set", ["hidden7"])
    assert glued == f"the key x_{REDACTED}_y is set", glued

    assert redact_values("hidden7 is set", ["hidden7"]) == f"{REDACTED} is set"
    quoted = redact_values("the key 'hidden7' is set", ["hidden7"])
    assert quoted == f"the key '{REDACTED}' is set", quoted
