# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""resolve_config's refusals, override handling, provenance and operator-path
record, on the shapes that quoted a value, dropped a setting or crashed.

- validate_config_document put pydantic's own text, which quotes every input
  (a value read from the environment included), into an operator file's refusal.
- read_config_document let a YAML constructor's ValueError (``!!int abc``)
  escape raw, with the file's text in its message.
- One reporters override that did not apply to the trusted base dropped every
  reporters override from the off-host reporter view, a disable included.
- The client-overrides sentinel, a relative path, was resolved against a
  working directory the load says may be gone.
- With that directory gone, the refusal of an override that needs it printed
  an appending key as ``key+``, and a rules name that happened to name a
  directory of the host (``etc``) was refused as a relative path.
- A quoted list item kept its quotes; a numeric-looking value could never set a
  string field.
- The provenance record listed a client's overrides among the operator's, so
  set_by_operator took a client's value for the operator's.
- The operator-paths record judged a tool path the workspace overlay or the
  trusted base named by the repository's own file.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
import yaml

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.resolve_config import (
    _parse_config_value,
    apply_config_overrides,
    read_config_document,
    resolve_config,
    validate_config_document,
)
from automated_security_helper.core.exceptions import (
    ASHConfigSourceError,
    ASHConfigValidationError,
)
from automated_security_helper.utils.config_trust import set_by_operator

pytestmark = pytest.mark.unit

ENV_VARIABLE = "ASH_REFUSAL_CANARY"
#: Long enough to be redacted wherever it appears, and unlike any other text.
ENV_VALUE = "qzbanana-value-5531"
TOOL_PATH_KEY = "scanners.bandit.options.config_file"


@pytest.fixture(autouse=True)
def _environment(monkeypatch):
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.delenv("ASH_MCP_WORKSPACE_ROOT", raising=False)


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def test_validate_config_document_quotes_no_environment_value(tmp_path, monkeypatch):
    monkeypatch.setenv(ENV_VARIABLE, ENV_VALUE)
    path = _write(
        tmp_path / "operator" / "ash.yaml",
        f"project_name: op\nfail_on_findings: !ENV ${{{ENV_VARIABLE}}}\n",
    )
    document = read_config_document(path)

    with pytest.raises(ASHConfigValidationError) as refused:
        validate_config_document(document, path)

    text = str(refused.value)
    assert ENV_VALUE not in text, text
    assert "fail_on_findings" in text, text
    assert refused.value.__cause__ is None


def test_read_config_document_refuses_a_yaml_constructor_error(tmp_path):
    path = _write(tmp_path / "operator" / "ash.yaml", "project_name: !!int abc\n")

    with pytest.raises(ASHConfigSourceError):
        read_config_document(path, log_failure=False)


def test_one_inapplicable_reporters_override_does_not_drop_the_others():
    from automated_security_helper.config.operator_only_options import reporter_section
    from automated_security_helper.config.resolve_config import _with_reporter_overrides
    from automated_security_helper.plugin_modules.ash_aws_plugins.security_hub_reporter import (
        SecurityHubReporter,
    )

    trusted = AshConfig.model_validate(
        {"project_name": "op", "reporters": {"aws-security-hub": {"enabled": True}}}
    )

    view = _with_reporter_overrides(
        trusted,
        [
            "reporters.aws-security-hub.enabled=notabool",
            "reporters.aws-security-hub.enabled=false",
        ],
        trusted,
    )

    section = reporter_section(view, SecurityHubReporter)
    enabled = section.get("enabled") if isinstance(section, dict) else section.enabled
    assert enabled is False, section


def _security_hub_enabled(view):
    from automated_security_helper.config.operator_only_options import reporter_section
    from automated_security_helper.plugin_modules.ash_aws_plugins.security_hub_reporter import (
        SecurityHubReporter,
    )

    section = reporter_section(view, SecurityHubReporter)
    return section.get("enabled") if isinstance(section, dict) else section.enabled


def test_an_enable_does_not_land_when_its_sections_sibling_override_fails():
    """All or nothing per reporter section: with the destination override
    refused by the trusted base, the enable beside it is dropped too, so the
    reporter does not send findings to the base's or the default destination."""
    from automated_security_helper.config.resolve_config import _with_reporter_overrides

    trusted = AshConfig.model_validate(
        {"project_name": "op", "reporters": {"aws-security-hub": {"enabled": False}}}
    )

    view = _with_reporter_overrides(
        trusted,
        [
            "reporters.aws-security-hub.enabled=true",
            "reporters.aws-security-hub.options=notamapping",
        ],
        trusted,
    )

    assert _security_hub_enabled(view) is False, view.reporters


def test_a_disable_lands_although_its_sections_sibling_override_fails():
    from automated_security_helper.config.resolve_config import _with_reporter_overrides

    trusted = AshConfig.model_validate(
        {"project_name": "op", "reporters": {"aws-security-hub": {"enabled": True}}}
    )

    view = _with_reporter_overrides(
        trusted,
        [
            "reporters.aws-security-hub.options=notamapping",
            "reporters.aws-security-hub.enabled=false",
        ],
        trusted,
    )

    assert _security_hub_enabled(view) is False, view.reporters


def test_another_sections_overrides_still_apply_when_one_section_fails():
    from automated_security_helper.config.resolve_config import _with_reporter_overrides

    trusted = AshConfig.model_validate(
        {
            "project_name": "op",
            "reporters": {
                "aws-security-hub": {"enabled": True},
                "cloudwatch-logs": {"enabled": True},
            },
        }
    )

    view = _with_reporter_overrides(
        trusted,
        [
            "reporters.cloudwatch-logs.options=notamapping",
            "reporters.aws-security-hub.enabled=false",
        ],
        trusted,
    )

    assert _security_hub_enabled(view) is False, view.reporters
    reporters = view.model_dump(by_alias=True)["reporters"]
    cloudwatch = reporters.get("cloudwatch-logs") or reporters.get("cloudwatch_logs")
    assert cloudwatch is not None and cloudwatch["enabled"] is True, reporters


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="the working directory cannot be removed while a process holds it",
)
def test_the_client_overrides_sentinel_is_skipped_before_resolving(
    tmp_path, monkeypatch
):
    from automated_security_helper.config.resolve_config import (
        CLIENT_OVERRIDES_SOURCE,
        _cached_documents,
    )

    gone = tmp_path / "gone"
    gone.mkdir()
    monkeypatch.chdir(gone)
    gone.rmdir()

    assert _cached_documents([CLIENT_OVERRIDES_SOURCE], {}) == []


def test_a_quoted_list_item_loses_its_quotes():
    assert _parse_config_value("['semgrep']") == ["semgrep"]
    assert _parse_config_value('["a", b]') == ["a", "b"]
    assert _parse_config_value("['true', 2]") == ["true", 2]


def test_an_override_can_set_a_string_field_to_digit_text():
    config = apply_config_overrides(AshConfig(), ["project_name=007"])

    assert config.project_name == "007"


def test_digit_text_an_override_set_joins_the_hidden_override_values():
    """The retyped text is an override's string value like any other, so a
    section's debug line hides it (an account id is one shape of it)."""
    config = apply_config_overrides(AshConfig(), ["project_name=007"])

    assert "007" in config._override_values, config._override_values


def test_an_override_that_does_not_apply_is_still_refused():
    with pytest.raises(ASHConfigValidationError):
        apply_config_overrides(AshConfig(), ["fail_on_findings=notabool"])


def test_a_clients_override_is_not_the_operators(tmp_path):
    operator = _write(
        tmp_path / "operator" / "ash.yaml", "project_name: op\nfail_on_findings: true\n"
    )
    (tmp_path / "repo").mkdir()

    config = resolve_config(
        config_path=operator,
        source_dir=tmp_path / "repo",
        config_overrides=["project_name=client"],
        client_overrides=True,
    )

    assert config.project_name == "client"
    assert set_by_operator(config, "project_name", "client") is False
    assert set_by_operator(config, "fail_on_findings", True) is True


def _tool_path(tmp_path: Path) -> Path:
    return _write(tmp_path / "operator" / "bandit.yaml", "skips: []\n")


def test_the_overlays_tool_path_is_the_operators_for_a_project_with_its_own_config(
    tmp_path,
):
    tool_path = _tool_path(tmp_path)
    project = _write(
        tmp_path / "repo" / ".ash" / ".ash.yaml",
        yaml.safe_dump({"project_name": "api"}),
    )
    operator = _write(
        tmp_path / "operator" / "ash.yaml",
        yaml.safe_dump(
            {
                "project_name": "op",
                "scanners": {"bandit": {"options": {"config_file": str(tool_path)}}},
            }
        ),
    )

    config = resolve_config(
        config_path=project,
        source_dir=tmp_path / "repo",
        trusted_config_path=operator,
        overlay_config_path=operator,
    )

    assert config._operator_paths.named(TOOL_PATH_KEY, tool_path) is True


def test_the_trusted_bases_tool_path_is_the_operators_over_a_repository_file(
    tmp_path, monkeypatch
):
    tool_path = _tool_path(tmp_path)
    operator = _write(
        tmp_path / "operator" / "ash.yaml",
        yaml.safe_dump(
            {
                "project_name": "op",
                "scanners": {"bandit": {"options": {"config_file": str(tool_path)}}},
            }
        ),
    )
    monkeypatch.setenv("ASH_CONFIG", str(operator))
    project = _write(
        tmp_path / "repo" / ".ash" / ".ash.yaml",
        yaml.safe_dump(
            {
                "project_name": "api",
                "scanners": {"bandit": {"options": {"config_file": ".bandit"}}},
            }
        ),
    )

    config = resolve_config(config_path=project, source_dir=tmp_path / "repo")

    assert config._operator_paths.named(TOOL_PATH_KEY, tool_path) is True


def test_the_own_writes_arm_records_the_anchored_tool_path(tmp_path):
    """An operator root that extends a repository file: only the root's own
    writes count, read as the merged configuration holds them (the relative
    tool path anchored to the root's directory), never as the raw file text."""
    from automated_security_helper.config.resolve_config import _operator_paths

    repo = tmp_path / "repo"
    base = _write(repo / ".ash" / "base.yaml", "project_name: base\n")
    root = _write(
        tmp_path / "operator" / "ash.yaml",
        f"extends: {base}\nscanners:\n  bandit:\n    options:\n"
        "      config_file: bandit.yaml\n",
    )
    anchored = tmp_path / "operator" / "bandit.yaml"
    written = {
        "extends": str(base),
        "scanners": {"bandit": {"options": {"config_file": "bandit.yaml"}}},
    }
    merged = {
        "project_name": "base",
        "scanners": {"bandit": {"options": {"config_file": str(anchored)}}},
    }

    record = _operator_paths(
        [base, root],
        [root, base],
        [root],
        repo,
        merged,
        untrusted=False,
        overrides=None,
        reads={root.resolve(): written},
    )

    assert record.named(TOOL_PATH_KEY, anchored) is True
    (document,) = record.documents
    assert "project_name" not in document, document


def _delete_the_working_directory(tmp_path, monkeypatch) -> None:
    # os.rmdir of the process's working directory is PermissionError on
    # Windows, so every deleted-directory case skips there through this helper.
    if sys.platform == "win32":
        pytest.skip("the working directory cannot be removed on Windows")
    gone = tmp_path / "gone"
    gone.mkdir()
    monkeypatch.chdir(gone)
    gone.rmdir()


def test_an_appending_override_is_named_as_written_with_no_working_directory(
    tmp_path, monkeypatch
):
    from automated_security_helper.config.resolve_config import (
        _anchored_operator_overrides,
    )

    _delete_the_working_directory(tmp_path, monkeypatch)

    with pytest.raises(ASHConfigValidationError) as refused:
        _anchored_operator_overrides(
            ["scanners.cfn-guard.options.rules_paths+=rules/zz-own.guard"]
        )

    text = str(refused.value)
    assert "scanners.cfn-guard.options.rules_paths+=" in text, text
    assert "rules_paths+ " not in text, text
    assert "zz-own" not in text, text


def test_a_rules_name_that_names_a_host_directory_passes_with_no_working_directory(
    tmp_path, monkeypatch
):
    """semgrep's ``config`` is anchored only when it names a file under the
    directory; ``etc`` names none under a working directory, so with a live one
    it passes as written, and the probe for a gone one must agree."""
    from automated_security_helper.config.resolve_config import (
        _anchored_operator_overrides,
    )

    _delete_the_working_directory(tmp_path, monkeypatch)

    assert _anchored_operator_overrides(["scanners.semgrep.options.config=etc"]) == [
        "scanners.semgrep.options.config=etc"
    ]


def test_a_path_that_climbs_out_of_its_root_is_refused_with_no_working_directory(
    tmp_path, monkeypatch
):
    """``../bandit.yaml`` normalizes to the same path under any one-deep root,
    so two placeholder roots agree on it; it is still taken from the working
    directory and is refused, naming the key and not the value."""
    from automated_security_helper.config.resolve_config import (
        _anchored_operator_overrides,
    )

    _delete_the_working_directory(tmp_path, monkeypatch)

    with pytest.raises(ASHConfigValidationError) as refused:
        _anchored_operator_overrides(
            ["scanners.bandit.options.config_file=../zz-climb.yaml"]
        )

    text = str(refused.value)
    assert "scanners.bandit.options.config_file" in text, text
    assert "zz-climb" not in text, text


@pytest.mark.parametrize(
    "override",
    [
        "scanners.bandit.options.config_file=/zz-elsewhere/bandit.yaml",
        "scanners.bandit.options.config_file=~/bandit.yaml",
        "scanners.cfn-guard.options.rules_paths+=/zz-elsewhere/own.guard",
    ],
)
def test_a_path_not_taken_from_the_directory_passes_with_no_working_directory(
    tmp_path, monkeypatch, override
):
    from automated_security_helper.config.resolve_config import (
        _anchored_operator_overrides,
    )

    _delete_the_working_directory(tmp_path, monkeypatch)

    assert _anchored_operator_overrides([override]) == [override]
