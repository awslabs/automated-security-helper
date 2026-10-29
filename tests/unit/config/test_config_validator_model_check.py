# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""ConfigValidator.check_config_file runs the loader and model a scan runs.

The CLI-level comparison with a real scan is in
tests/unit/cli/test_config_validate_agrees_with_scan.py; these pin the pieces.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.config import config_app
from automated_security_helper.config.config_sources import uses_env_references
from automated_security_helper.config.config_validator import ConfigValidator


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(text).lstrip(), encoding="utf-8")
    return path


def test_model_errors_are_errors_and_structure_problems_are_warnings(tmp_path):
    cfg = _write(
        tmp_path / ".ash.yaml",
        """
        project_name: demo
        fail_on_findings: banana
        foo_unknown: 1
        scanners:
          bandit:
            name: bandit
        """,
    )

    check = ConfigValidator.check_config_file(cfg)

    assert check.errors == [
        "Invalid value at 'fail_on_findings': Input should be a valid boolean"
    ]
    assert not check.scan_accepts
    assert any("foo_unknown" in w for w in check.warnings), check.warnings
    assert any("internal-only field 'name'" in w for w in check.warnings)


@pytest.mark.parametrize(
    ("segment", "section", "field_line", "kind", "field", "hint"),
    [
        (
            "scanners",
            "bandit",
            "tool_version: '1.7.5'",
            "Scanner",
            "tool_version",
            # bandit declares a tool_version option.
            "; if you meant a version constraint, put it under options",
        ),
        ("scanners", "cdk-nag", "extension: txt", "Scanner", "extension", ""),
        (
            "converters",
            "archive",
            "install_timeout: 10",
            "Converter",
            "install_timeout",
            "",
        ),
    ],
)
def test_an_internal_field_a_scan_refuses_is_reported_once_as_an_error(
    tmp_path, segment, section, field_line, kind, field, hint
):
    """A scan refuses a key a built-in plugin's section does not declare.

    The internal-only fields older ``ash config init`` versions wrote are among
    those keys. The model refuses each in the internal-only wording whose lint
    fix removes it, not with "move tool_version under options": for a leaked
    tool_version that advice would turn it into a version constraint. The
    check reports that refusal once, as an error, in the words the scan prints.
    """
    cfg = _write(
        tmp_path / ".ash.yaml",
        f"project_name: demo\n{segment}:\n  {section}:\n    {field_line}\n",
    )

    check = ConfigValidator.check_config_file(cfg)

    assert check.errors == [
        (
            f"Invalid value at '{segment}.{section}': Value error, "
            f"{kind} '{section}' contains internal-only field '{field}' - "
            f"this should not be in user configs{hint}."
        )
    ]
    assert not check.scan_accepts
    assert not any(field in w for w in check.warnings), check.warnings


def test_an_internal_field_the_section_declares_stays_a_warning(tmp_path):
    """``name``, and a reporter's ``extension``, are declared, so a scan accepts them."""
    cfg = _write(
        tmp_path / ".ash.yaml",
        """
        project_name: demo
        scanners:
          bandit:
            name: bandit
        reporters:
          html:
            extension: html
        """,
    )

    check = ConfigValidator.check_config_file(cfg)

    assert check.errors == []
    assert sorted(w for w in check.warnings if "internal-only field" in w) == [
        (
            "Reporter 'html' contains internal-only field 'extension' - "
            "this should not be in user configs"
        ),
        (
            "Scanner 'bandit' contains internal-only field 'name' - "
            "this should not be in user configs"
        ),
    ]


def test_an_internal_field_a_patch_removes_stays_a_warning(tmp_path):
    """The file still sets the field, but the config a scan loads does not hold it."""
    cfg = _write(
        tmp_path / ".ash.yaml",
        """
        project_name: demo
        scanners:
          bandit:
            tool_version: '1.7.5'
        patch:
          - op: remove
            path: /scanners/bandit/tool_version
        """,
    )

    check = ConfigValidator.check_config_file(cfg)

    assert check.errors == []
    assert [w for w in check.warnings if "tool_version" in w] == [
        (
            "Scanner 'bandit' contains internal-only field 'tool_version' - "
            "this should not be in user configs"
        )
    ]


def test_a_refused_internal_field_leaves_the_rest_of_its_section_checked(tmp_path):
    """The model still checks what else the section holds, and says so once."""
    cfg = _write(
        tmp_path / ".ash.yaml",
        """
        project_name: demo
        scanners:
          bandit:
            tool_version: '1.7.5'
            severity_threshold: HIGH
        """,
    )

    check = ConfigValidator.check_config_file(cfg)

    assert check.errors == [
        (
            "Invalid value at 'scanners.bandit': Value error, "
            "Scanner 'bandit' contains internal-only field 'tool_version' - "
            "this should not be in user configs; if you meant a version "
            "constraint, put it under options. "
            "scanners.bandit.severity_threshold is not a section-level key; "
            "move severity_threshold under options."
        ),
    ]
    assert not any("tool_version" in w for w in check.warnings), check.warnings


def test_an_internal_field_only_an_extends_base_sets_is_not_the_files_to_fix(tmp_path):
    """The refusal names the field, but the file being checked does not hold it.

    lint --fix edits that file only, so the field is not reported as one it
    removes: the base is where the operator has to edit.
    """
    _write(tmp_path / "base.yaml", "scanners:\n  bandit:\n    tool_version: '1.7.5'\n")
    cfg = _write(tmp_path / ".ash.yaml", "extends: base.yaml\nproject_name: demo\n")

    check = ConfigValidator.check_config_file(cfg)

    assert len(check.errors) == 1, check.errors
    assert "contains internal-only field 'tool_version'" in check.errors[0]
    assert (
        ConfigValidator.internal_fields_refused(check.errors[0], check.config_data)
        == []
    )


def test_a_section_spelled_the_other_way_is_still_matched_to_its_warning(tmp_path):
    """The model names cdk-nag's section by its own spelling, whichever the file uses.

    The refused field is matched to the file's ``cdk_nag`` all the same, so it is
    not also warned about.
    """
    cfg = _write(
        tmp_path / ".ash.yaml",
        """
        project_name: demo
        scanners:
          cdk_nag:
            tool_version: '1'
        """,
    )

    check = ConfigValidator.check_config_file(cfg)

    assert check.errors == [
        (
            "Invalid value at 'scanners.cdk-nag': Value error, "
            "Scanner 'cdk-nag' contains internal-only field 'tool_version' - "
            "this should not be in user configs."
        )
    ]
    assert not any("tool_version" in w for w in check.warnings), check.warnings
    assert ConfigValidator.internal_fields_refused(
        check.errors[0], {"scanners": {"cdk_nag": {"tool_version": "1"}}}
    ) == [("scanners", "cdk_nag", "tool_version")]


def test_error_location_reaches_into_lists(tmp_path):
    cfg = _write(
        tmp_path / ".ash.yaml",
        """
        project_name: demo
        global_settings:
          suppressions:
            - rule_id: B101
              path: tests/**
        """,
    )

    check = ConfigValidator.check_config_file(cfg)

    assert any(
        e.startswith("Invalid value at 'global_settings.suppressions[0].reason'")
        for e in check.errors
    ), check.errors
    assert (
        ConfigValidator.model_error_location(check.errors[0])
        == "global_settings.suppressions[0].reason"
    )


@pytest.mark.parametrize(
    "field_text",
    [
        pytest.param(
            "fail_on_findings: !ENV ${ASH_TEST_SECRET_VALUE:false}", id="bool"
        ),
        pytest.param(
            "global_settings:\n  suppressions:\n    - rule_id: B101\n"
            "      path: a.py\n      reason: r\n"
            "      expiration: ${ASH_TEST_SECRET_VALUE:2099-01-01}",
            id="expiration",
        ),
    ],
)
def test_error_does_not_quote_the_value(tmp_path, monkeypatch, field_text):
    # A value may come from the environment, and this message goes to CI logs.
    # The default form, so the reference resolves (see the unset-variable note in
    # docs/content/docs/config-overrides.md).
    monkeypatch.setenv("ASH_TEST_SECRET_VALUE", "s3cr3t-value-from-env")
    cfg = tmp_path / ".ash.yaml"
    cfg.write_text(f"project_name: demo\n{field_text}\n", encoding="utf-8")

    check = ConfigValidator.check_config_file(cfg)

    assert check.errors, "the resolved string is not valid there"
    assert all("s3cr3t-value-from-env" not in e for e in check.errors), check.errors


def test_env_references_resolve_as_in_a_scan(tmp_path, monkeypatch):
    monkeypatch.delenv("ASH_TEST_PROJECT", raising=False)
    cfg = _write(
        tmp_path / ".ash.yaml",
        """
        project_name: !ENV ${ASH_TEST_PROJECT:demo}
        """,
    )

    check = ConfigValidator.check_config_file(cfg)

    assert check.errors == []
    assert check.warnings == []


def test_overrides_are_checked_after_the_file(tmp_path):
    cfg = _write(tmp_path / ".ash.yaml", "project_name: demo\n")

    assert ConfigValidator.check_config_file(cfg).scan_accepts
    bad = ConfigValidator.check_config_file(
        cfg, config_overrides=["fail_on_findings=maybe"]
    )
    # Overrides are applied as a scan applies them (non-strict, so the message
    # differs slightly from a strict file check's).
    assert len(bad.errors) == 1, bad.errors
    assert bad.errors[0].startswith(
        "Invalid value at 'fail_on_findings': Input should be a valid boolean"
    )
    assert bad.errors[0].endswith("(after --config-overrides)")
    malformed = ConfigValidator.check_config_file(cfg, config_overrides=["no-equals"])
    assert len(malformed.errors) == 1
    assert "Invalid config override: 'no-equals'" in malformed.errors[0]


def test_validate_config_file_lists_every_problem(tmp_path):
    """The (is_valid, problems) API: model errors first, then the warnings."""
    cfg = _write(
        tmp_path / ".ash.yaml",
        """
        fail_on_findings: banana
        foo_unknown: 1
        """,
    )

    is_valid, problems = ConfigValidator.validate_config_file(cfg)

    assert not is_valid
    assert problems[0].startswith("Invalid value at 'fail_on_findings'")
    # In its old wording here, which the MCP validate_config tool types from.
    assert ConfigValidator.LEGACY_MISSING_PROJECT_NAME_MESSAGE in problems
    assert any("foo_unknown" in p for p in problems)


@pytest.mark.parametrize(
    "text, expected",
    [
        pytest.param("x: !ENV ${ASH_X:1}\n", True, id="tag"),
        pytest.param("x: ${ASH_X:1}\n", True, id="implicit"),
        pytest.param("x:\n  - y: ${ASH_X}\n", True, id="nested"),
        pytest.param("x: '${ASH_X}'\n", False, id="quoted-is-a-string"),
        pytest.param("# !ENV ${ASH_X}\nx: 1\n", False, id="comment"),
        pytest.param("x: [unclosed\n", False, id="unparseable"),
    ],
)
def test_uses_env_references(tmp_path, text, expected):
    path = tmp_path / "c.yaml"
    path.write_text(text, encoding="utf-8")
    assert uses_env_references(path) is expected


def test_lint_fix_refuses_a_file_with_env_references(tmp_path):
    """--fix writes parsed values back, which would bake in the resolved values."""
    cfg = _write(
        tmp_path / ".ash" / ".ash.yaml",
        """
        project_name: !ENV ${ASH_TEST_PROJECT:demo}
        scanners:
          bandit:
            name: bandit
        """,
    )
    before = cfg.read_text(encoding="utf-8")

    result = CliRunner().invoke(
        config_app, ["lint", "--config", str(cfg), "--fix", "--non-interactive"]
    )

    assert result.exit_code == 1, result.output
    assert "!ENV" in result.output
    assert cfg.read_text(encoding="utf-8") == before


@pytest.mark.parametrize(
    "line",
    [
        "global_settings: 5",
        "global_settings: {suppressions: 5}",
        "global_settings: {suppressions: [5]}",
        "global_settings: {suppressions: [{path: 5, rule_id: 1, reason: r, line_start: x}]}",
        "global_settings: {suppressions: [{path: a, rule_id: b, reason: r, expiration: 5}]}",
        "global_settings: {suppressions: [{path: a, rule_id: b, reason: r, expiration: 2099-01-31}]}",
        "global_settings: {suppressions: [{path: a, rule_id: b, reason: [1, 2]}]}",
        "global_settings: {suppressions: [{path: a, rule_id: b, reason: r, symbol: 5}]}",
        "global_settings: {ignore_paths: {a: 1}}",
        "global_settings: {ignore_paths: [5]}",
        "global_settings: {ignore_paths: [{path: 5, reason: r}]}",
        "scanners: 5",
        "scanners: {bandit: 5}",
        "scanners: [1]",
        "reporters: [1]",
        "converters: x",
        "fail_on_findings: [1]",
    ],
)
def test_wrong_types_exit_three_without_a_traceback(tmp_path, line):
    """Every lint and validate check survives a value of the wrong type.

    A lint check given one (an int or an unquoted YAML date where strptime wants
    text, an int path where `in` wants a string) names the field and exits 3, with
    no traceback.
    """
    cfg = _write(tmp_path / "c.yaml", f"project_name: x\n{line}\n")
    runner = CliRunner()

    for command in ("lint", "validate"):
        result = runner.invoke(config_app, [command, "--config", str(cfg)])
        assert result.exception is None or isinstance(result.exception, SystemExit), (
            command,
            result.exception,
        )
        assert result.exit_code == 3, (command, result.output)
        # lint may report the field in its own words (a bad symbol, say), but
        # marks what blocks the scan either way.
        marker = "[blocks the scan]" if command == "lint" else "Invalid value at '"
        assert marker in result.output, (command, result.output)


@pytest.mark.parametrize("extends", [False, True], ids=["one-file", "extends"])
@pytest.mark.parametrize("command", ["lint", "validate"])
def test_each_file_is_parsed_once(tmp_path, monkeypatch, command, extends):
    """Each parse resolves every !ENV reference again and logs its warning again.

    Counted at the YAML loader rather than in the output, because the log handler's
    stream is not reliably the one CliRunner captures. With `extends`, the chain is
    two files, and each is parsed once.
    """
    import automated_security_helper.config.config_sources as config_sources

    parses = []
    real_loader = config_sources.load_yaml_config

    def counting_loader(stream):
        parses.append(stream)
        return real_loader(stream)

    monkeypatch.setattr(config_sources, "load_yaml_config", counting_loader)
    text = "project_name: !ENV ${ASH_TEST_UNSET_NAME:demo}\n"
    if extends:
        _write(
            tmp_path / "base.yaml",
            "global_settings:\n  severity_threshold: !ENV ${ASH_TEST_UNSET_LEVEL:LOW}\n",
        )
        text = "extends: base.yaml\n" + text
    cfg = _write(tmp_path / ".ash.yaml", text)
    monkeypatch.chdir(tmp_path)

    result = CliRunner().invoke(config_app, [command, "--config", str(cfg)])

    assert result.exit_code == 0, result.output
    assert len(parses) == (2 if extends else 1), parses


def test_extends_chain_is_reported(tmp_path):
    base = _write(tmp_path / "base.yaml", "project_name: base\n")
    child = _write(
        tmp_path / "child.yaml", "extends: base.yaml\nfail_on_findings: false\n"
    )

    check = ConfigValidator.check_config_file(child)

    assert check.scan_accepts, check
    assert [p.resolve() for p in check.chain] == [base.resolve(), child.resolve()]
    result = CliRunner().invoke(config_app, ["validate", "--config", str(child)])
    assert "Resolved source chain" in result.output


def test_lint_fix_passes_a_clean_file_with_env_references(tmp_path):
    """`lint --fix --non-interactive` is the pre-commit recipe; with nothing to fix
    it must not refuse a file for using !ENV."""
    cfg = _write(
        tmp_path / ".ash" / ".ash.yaml",
        """
        project_name: !ENV ${ASH_TEST_PROJECT:demo}
        """,
    )
    before = cfg.read_text(encoding="utf-8")

    result = CliRunner().invoke(
        config_app, ["lint", "--config", str(cfg), "--fix", "--non-interactive"]
    )

    assert result.exit_code == 0, result.output
    assert cfg.read_text(encoding="utf-8") == before


def test_a_json_schema_key_is_not_a_warning(tmp_path):
    cfg = tmp_path / ".ash.json"
    cfg.write_text(
        '{"$schema": "https://example.invalid/AshConfig.json", "project_name": "demo"}',
        encoding="utf-8",
    )

    check = ConfigValidator.check_config_file(cfg)

    assert check.errors == [] and check.warnings == [], check


def test_an_unknown_key_warning_says_what_a_scan_does(tmp_path):
    cfg = _write(tmp_path / ".ash.yaml", "project_name: demo\nfoo_unknown: 1\n")

    (warning,) = ConfigValidator.check_config_file(cfg).warnings

    assert "a scan ignores it" in warning


@pytest.mark.parametrize(
    "text, field",
    [
        pytest.param(
            "project_name: demo\nfail_on_findings: 1\n",
            "fail_on_findings",
            id="model-error",
        ),
        pytest.param(
            "project_name: demo\nlegacy_option: 1\n",
            "legacy_option",
            id="unknown-field",
        ),
        pytest.param(
            "project_name: demo\nfail_on_findings: true\nfail_on_findings: false\n",
            "fail_on_findings",
            id="duplicate-field",
        ),
        pytest.param(
            "fail_on_findings: false\n", "project_name", id="missing-project-name"
        ),
    ],
)
def test_a_lint_issue_names_its_field_once(tmp_path, text, field):
    from automated_security_helper.config.config_linter import ConfigLinter

    cfg = _write(tmp_path / ".ash.yaml", text)

    (issue,) = [i for i in ConfigLinter.lint(cfg).issues if i.path == field]

    assert str(issue).count(field) == 1, str(issue)


@pytest.mark.parametrize(
    "text, value",
    [
        pytest.param(
            "base a/srv/secret end", "/srv/secret", id="starts-with-a-separator"
        ),
        pytest.param("base x-secret-y end", "x-secret-", id="ends-with-a-separator"),
        pytest.param("at 'abcd'", "abcd", id="quoted-word"),
    ],
)
def test_redaction_replaces_the_value_wherever_it_starts(text, value):
    from automated_security_helper.config.config_validator import redact_values

    assert value not in redact_values(text, [value])


def test_the_date_hint_is_not_typed_as_a_parse_error(tmp_path):
    from automated_security_helper.cli.mcp_tools import mcp_validate_config

    result = mcp_validate_config(
        config_content=(
            "project_name: demo\nglobal_settings:\n  suppressions:\n"
            "    - rule_id: B101\n      path: a.py\n      reason: r\n"
            "      expiration: 2099-01-31\n"
        )
    )

    (error,) = result["errors"]
    assert error["type"] != "yaml_parse_error", error
    assert error["field"] == "global_settings.suppressions[0].expiration", error


def test_every_key_the_model_reads_is_a_known_top_level_field():
    """The validator's list of top-level keys is the model's, both spellings.

    A key the model reads but the list lacks was reported as "a scan ignores
    it" (mcp_resource_management, the field name of mcp-resource-management),
    while the scan applied it.
    """
    from automated_security_helper.config.ash_config import AshConfig

    spellings = {
        spelling
        for name, info in AshConfig.model_fields.items()
        for spelling in (name, info.alias)
        if spelling
    }

    assert ConfigValidator.VALID_TOP_LEVEL_FIELDS - {"$schema"} == (
        spellings - ConfigValidator.INVALID_TOP_LEVEL_FIELDS
    )


def test_both_spellings_of_one_key_say_which_a_scan_reads(tmp_path):
    from automated_security_helper.config.resolve_config import resolve_config

    cfg = _write(
        tmp_path / ".ash.yaml",
        """
        project_name: demo
        mcp_resource_management:
          max_concurrent_scans: 2
        mcp-resource-management:
          max_concurrent_scans: 3
        """,
    )

    check = ConfigValidator.check_config_file(cfg)

    assert (
        resolve_config(
            cfg, fallback_to_default=False
        ).mcp_resource_management.max_concurrent_scans
        == 3
    )
    (warning,) = [w for w in check.warnings if "mcp_resource_management" in w]
    assert "a scan reads 'mcp-resource-management'" in warning, warning
    assert check.errors == []


def test_both_plugin_spellings_say_which_a_scan_reads(tmp_path):
    from automated_security_helper.config.config_linter import ConfigLinter
    from automated_security_helper.config.resolve_config import resolve_config

    for first, second in (("cdk_nag", "cdk-nag"), ("cdk-nag", "cdk_nag")):
        enabled = {"cdk-nag": "true", "cdk_nag": "false"}
        cfg = _write(
            tmp_path / ".ash.yaml",
            f"""
            project_name: demo
            scanners:
              {first}:
                enabled: {enabled[first]}
              {second}:
                enabled: {enabled[second]}
            """,
        )

        result = ConfigLinter.lint(cfg)

        assert (
            resolve_config(cfg, fallback_to_default=False).scanners.cdk_nag.enabled
            is True
        )
        (issue,) = [i for i in result.issues if "cdk_nag" in i.message]
        assert issue.severity.value == "warning", str(issue)
        assert "a scan reads 'cdk-nag'" in issue.message, str(issue)


def test_a_patch_that_replaces_the_root_is_reported_as_the_scan_reports_it(tmp_path):
    """The patched document is not a mapping. The check fell back to the file's
    own keys, which the model refuses with a developer's message about
    AshConfig.from_file; the scan says the document is not a mapping."""
    from automated_security_helper.config.resolve_config import resolve_config
    from automated_security_helper.core.exceptions import ASHConfigValidationError

    cfg = _write(
        tmp_path / ".ash.yaml",
        """
        project_name: demo
        patch:
          - op: replace
            path: ""
            value: [1, 2]
        """,
    )

    check = ConfigValidator.check_config_file(cfg)
    with pytest.raises(ASHConfigValidationError) as raised:
        resolve_config(cfg, fallback_to_default=False)

    expected = (
        "Invalid value at '(top level)': Input should be a valid dictionary or "
        "instance of AshConfig"
    )
    assert check.errors == [expected], check.errors
    assert check.errors[0] in str(raised.value)
    assert not any("from_file" in w for w in check.warnings), check.warnings


def test_the_checks_chain_load_classifies_repository_files_as_a_scan_does(
    tmp_path,
):
    """The check hands the loader the same repository classification a scan
    uses, so a config inside the scanned tree writing an option only the
    operator sets draws the scan-ignores warning, while the identical file
    outside every checkout is the operator's and draws none. A load without
    the classification treats the in-tree file as the operator's too and
    says nothing."""
    from tests.utils.helpers import mark_git_checkout

    body = """
    project_name: demo
    reporters:
      aws-security-hub:
        enabled: true
        options:
          findings_scope: suppressed
    """
    src = tmp_path / "src"
    mark_git_checkout(src)
    inside = _write(src / ".ash" / ".ash.yaml", body)
    check = ConfigValidator.check_config_file(inside, source_dir=src)
    assert any(
        "findings_scope" in warning and "a scan ignores" in warning
        for warning in check.warnings
    ), check.warnings

    outside = _write(tmp_path / "plain" / "ash.yaml", body)
    control = ConfigValidator.check_config_file(outside, source_dir=src)
    assert not any("findings_scope" in warning for warning in control.warnings), (
        control.warnings
    )
