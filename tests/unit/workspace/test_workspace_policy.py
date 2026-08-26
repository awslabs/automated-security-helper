# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the workspace-level policy file.

These are the acceptance criteria for Phase 3 (criteria 7, 19, 20, 21).

Two biases run through the whole file, and they point in opposite directions on
purpose:

* **The ceiling may only tighten.** ``max_severity_threshold`` names the loosest
  a project may be, so a project that is already stricter is left exactly as it
  was. A test that cannot tell "tightened" from "replaced" is worthless here,
  so every threshold case asserts the untouched direction as well.
* **A pushed-down pattern may only narrow.** A workspace suppression that ASH
  cannot rewrite soundly for a project is refused, and one that cannot match
  inside a project is not passed to it. Over-suppression is the dangerous
  direction because a suppressed finding leaves no trace -- see
  ``utils/workspace_paths.py``.
"""

import json

import pytest
from pydantic import ValidationError

from automated_security_helper.config.ash_workspace_config import (
    AshWorkspaceConfig,
    WorkspacePolicyConfig,
)
from automated_security_helper.core.exceptions import (
    WorkspaceDefinitionError,
    WorkspacePatternError,
)
from automated_security_helper.models.core import (
    AshSuppression,
    IgnorePathWithReason,
)
from automated_security_helper.workspace.policy import (
    WORKSPACE_POLICY_FILE_NAMES,
    policy_for_project,
    resolve_workspace_policy,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _policy(**fields):
    """A WorkspacePolicyConfig with *fields* set and everything else default."""
    return WorkspacePolicyConfig(**fields)


def _write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _suppression(path, **extra):
    return AshSuppression(path=path, reason="test", **extra)


# ---------------------------------------------------------------------------
# 1. The schema itself
# ---------------------------------------------------------------------------


def test_an_empty_policy_file_is_valid_and_carries_no_policy():
    """A policy file that sets nothing must not invent a threshold.

    Defaulting max_severity_threshold to MEDIUM here would silently tighten
    every project in a workspace whose operator wrote an empty file.
    """
    config = AshWorkspaceConfig()
    assert config.workspace.max_severity_threshold is None
    assert config.workspace.suppressions == []
    assert config.workspace.ignore_paths == []
    assert config.workspace.additional_scanners == []
    assert config.workspace.policy_scanners_gate is False


def test_an_unknown_policy_key_is_refused():
    """extra=forbid, so a typo is an error rather than a silently ignored key."""
    with pytest.raises(ValidationError):
        AshWorkspaceConfig.model_validate(
            {"workspace": {"max_severity_threshhold": "HIGH"}}
        )


def test_an_unknown_top_level_key_is_refused():
    with pytest.raises(ValidationError):
        AshWorkspaceConfig.model_validate({"global_settings": {}})


@pytest.mark.parametrize("value", ["ALL", "LOW", "MEDIUM", "HIGH", "CRITICAL"])
def test_every_ladder_value_is_accepted_as_a_ceiling(value):
    config = AshWorkspaceConfig.model_validate(
        {"workspace": {"max_severity_threshold": value}}
    )
    assert config.workspace.max_severity_threshold == value


@pytest.mark.parametrize("value", ["medium", "SEVERE", "", "NONE"])
def test_an_off_ladder_ceiling_is_refused(value):
    """The ladder is case-sensitive, so 'medium' must not be accepted.

    severity_ladder gates an unrecognised threshold like CRITICAL -- the
    loosest setting -- so accepting 'medium' here would quietly turn a ceiling
    the operator meant as MEDIUM into no ceiling at all.
    """
    with pytest.raises(ValidationError):
        AshWorkspaceConfig.model_validate(
            {"workspace": {"max_severity_threshold": value}}
        )


def test_the_generated_schema_includes_the_workspace_config():
    """The lint job regenerates schemas and fails on a diff, so it must be listed."""
    from automated_security_helper.schemas.generate_schemas import generate_schemas

    schemas = generate_schemas("dict")
    assert "AshWorkspaceConfig" in schemas
    properties = schemas["AshWorkspaceConfig"]["properties"]
    assert "workspace" in properties


# ---------------------------------------------------------------------------
# 2. The ceiling tightens a lax project and leaves a strict one alone
# ---------------------------------------------------------------------------


def test_a_project_looser_than_the_ceiling_is_tightened():
    """CRITICAL is the loosest setting, so a MEDIUM ceiling must pull it in."""
    resolved = policy_for_project(
        _policy(max_severity_threshold="MEDIUM"),
        project_prefix="api",
        project_threshold="CRITICAL",
        project_scanners=(),
    )
    assert resolved.effective_threshold == "MEDIUM"
    assert resolved.threshold_tightened is True


def test_a_project_stricter_than_the_ceiling_is_untouched():
    """LOW is stricter than MEDIUM, so the ceiling must not loosen it to MEDIUM."""
    resolved = policy_for_project(
        _policy(max_severity_threshold="MEDIUM"),
        project_prefix="api",
        project_threshold="LOW",
        project_scanners=(),
    )
    assert resolved.effective_threshold == "LOW"
    assert resolved.threshold_tightened is False


def test_the_strictest_project_setting_survives_the_loosest_ceiling():
    resolved = policy_for_project(
        _policy(max_severity_threshold="CRITICAL"),
        project_prefix="api",
        project_threshold="ALL",
        project_scanners=(),
    )
    assert resolved.effective_threshold == "ALL"
    assert resolved.threshold_tightened is False


def test_no_ceiling_leaves_the_project_threshold_exactly_as_it_was():
    resolved = policy_for_project(
        _policy(),
        project_prefix="api",
        project_threshold="CRITICAL",
        project_scanners=(),
    )
    assert resolved.effective_threshold == "CRITICAL"
    assert resolved.threshold_tightened is False


def test_a_project_with_the_gate_turned_off_is_still_tightened_by_the_ceiling():
    """A falsy project threshold means "nothing fails", which is looser than any
    ceiling. The ceiling has to reach it, or an operator could opt out of
    workspace policy by deleting their own threshold."""
    resolved = policy_for_project(
        _policy(max_severity_threshold="HIGH"),
        project_prefix="api",
        project_threshold=None,
        project_scanners=(),
    )
    assert resolved.effective_threshold == "HIGH"
    assert resolved.threshold_tightened is True


@pytest.mark.parametrize(
    "project,ceiling,expected",
    [
        ("CRITICAL", "HIGH", "HIGH"),
        ("CRITICAL", "MEDIUM", "MEDIUM"),
        ("HIGH", "MEDIUM", "MEDIUM"),
        ("HIGH", "CRITICAL", "HIGH"),
        ("MEDIUM", "MEDIUM", "MEDIUM"),
        ("LOW", "HIGH", "LOW"),
        ("ALL", "LOW", "ALL"),
    ],
)
def test_the_effective_threshold_is_the_stricter_of_the_two(project, ceiling, expected):
    """The RFC's worked table, plus the untouched direction for each row."""
    resolved = policy_for_project(
        _policy(max_severity_threshold=ceiling),
        project_prefix="api",
        project_threshold=project,
        project_scanners=(),
    )
    assert resolved.effective_threshold == expected


def test_the_effective_threshold_is_never_looser_than_the_project_asked_for():
    """Property: over every pair, the ceiling can only tighten or do nothing.

    The strictness order is spelled out here rather than imported from
    severity_ladder ON PURPOSE. Asserting against ``stricter_of`` would compare
    the implementation to itself -- both sides would derive from the same
    function, so an inverted ladder would satisfy the test. This table is an
    independent statement of the order the RFC specifies, so if the two ever
    disagree the test fails rather than agreeing with the bug.
    """
    # Strictest first. Raising a threshold LOOSENS the gate.
    order = ["ALL", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

    checked = 0
    for project in order:
        for ceiling in order:
            resolved = policy_for_project(
                _policy(max_severity_threshold=ceiling),
                project_prefix="api",
                project_threshold=project,
                project_scanners=(),
            )
            effective = resolved.effective_threshold

            # The result is one of the two inputs, and it is the stricter one --
            # i.e. the earlier one in the order above.
            assert effective in (project, ceiling)
            assert order.index(effective) == min(
                order.index(project), order.index(ceiling)
            ), f"project={project} ceiling={ceiling} gave {effective}"
            # And never looser than the project already was.
            assert order.index(effective) <= order.index(project)
            checked += 1

    assert checked == len(order) ** 2


# ---------------------------------------------------------------------------
# 3. Suppressions and ignore_paths are pushed DOWN into each project
# ---------------------------------------------------------------------------


def test_a_suppression_anchored_at_one_project_reaches_only_that_project():
    """The whole point of the push-down: api's suppression must not silence web."""
    policy = _policy(suppressions=[_suppression("api/src/legacy.py")])

    for_api = policy_for_project(
        policy,
        project_prefix="api",
        project_threshold="MEDIUM",
        project_scanners=(),
    )
    for_web = policy_for_project(
        policy,
        project_prefix="web",
        project_threshold="MEDIUM",
        project_scanners=(),
    )

    assert [s.path for s in for_api.suppressions] == ["src/legacy.py"]
    assert for_web.suppressions == ()


def test_a_double_star_suppression_reaches_every_project():
    policy = _policy(suppressions=[_suppression("**/generated.py")])

    for prefix in ("api", "web", "services/worker"):
        resolved = policy_for_project(
            policy,
            project_prefix=prefix,
            project_threshold="MEDIUM",
            project_scanners=(),
        )
        assert [s.path for s in resolved.suppressions] == ["**/generated.py"], prefix


def test_a_suppression_naming_only_the_project_directory_is_not_passed_down():
    """ "api" matches the path "api", not "api/src/x.py", so it covers no file.

    Passing "**" here would suppress an entire project the operator never asked
    to silence -- the failure the workspace_paths contract sweep caught.
    """
    policy = _policy(suppressions=[_suppression("api")])
    resolved = policy_for_project(
        policy,
        project_prefix="api",
        project_threshold="MEDIUM",
        project_scanners=(),
    )
    assert resolved.suppressions == ()


def test_an_unrewritable_suppression_is_refused_and_names_the_pattern():
    """A pattern with no sound single-pattern rewrite must not be dropped quietly.

    Dropping it would leave the operator's stated policy unapplied with nothing
    in the output to say so; ``*/sub/*.py`` is the two-glob-semantics case from
    workspace_paths.
    """
    policy = _policy(suppressions=[_suppression("*/sub/*.py")])
    with pytest.raises((WorkspaceDefinitionError, WorkspacePatternError)) as excinfo:
        policy_for_project(
            policy,
            project_prefix="api",
            project_threshold="MEDIUM",
            project_scanners=(),
        )
    assert "*/sub/*.py" in str(excinfo.value)


def test_ignore_paths_are_pushed_down_the_same_way_as_suppressions():
    policy = _policy(
        ignore_paths=[
            IgnorePathWithReason(path="api/vendor/**", reason="third party"),
            IgnorePathWithReason(path="web/dist/**", reason="build output"),
        ]
    )
    resolved = policy_for_project(
        policy,
        project_prefix="api",
        project_threshold="MEDIUM",
        project_scanners=(),
    )
    assert [p.path for p in resolved.ignore_paths] == ["vendor/**"]


def test_everything_except_the_path_survives_the_push_down_unchanged():
    """Rewriting the path must not drop the rule_id, reason, lines or expiry.

    A suppression that loses its rule_id widens from "this rule here" to
    "every rule here".
    """
    policy = _policy(
        suppressions=[
            AshSuppression(
                path="api/src/x.py",
                reason="tracked in TICKET-1",
                rule_id="B101",
                line_start=10,
                line_end=20,
                expiration="2099-01-01",
            )
        ]
    )
    resolved = policy_for_project(
        policy,
        project_prefix="api",
        project_threshold="MEDIUM",
        project_scanners=(),
    )

    (pushed,) = resolved.suppressions
    assert pushed.path == "src/x.py"
    assert pushed.reason == "tracked in TICKET-1"
    assert pushed.rule_id == "B101"
    assert pushed.line_start == 10
    assert pushed.line_end == 20
    assert pushed.expiration == "2099-01-01"


def test_the_pushed_down_suppression_is_a_copy_not_the_policy_object():
    """Each project gets its own object, or rewriting one would rewrite all.

    The policy is shared across projects, so mutating in place would leave the
    second project's push-down operating on the first project's coordinates.
    """
    original = _suppression("api/src/x.py")
    policy = _policy(suppressions=[original])
    resolved = policy_for_project(
        policy,
        project_prefix="api",
        project_threshold="MEDIUM",
        project_scanners=(),
    )
    assert resolved.suppressions[0] is not original
    assert original.path == "api/src/x.py"


# ---------------------------------------------------------------------------
# 4. additional_scanners are additive, and policy-origin ones do not gate
# ---------------------------------------------------------------------------


def test_a_scanner_the_project_already_declares_is_not_policy_origin():
    """It runs under the project's own config, so it is the project's finding."""
    resolved = policy_for_project(
        _policy(additional_scanners=["bandit"]),
        project_prefix="api",
        project_threshold="MEDIUM",
        project_scanners=("bandit", "checkov"),
    )
    assert resolved.policy_scanners == ()


def test_a_scanner_only_the_policy_names_is_policy_origin():
    resolved = policy_for_project(
        _policy(additional_scanners=["semgrep"]),
        project_prefix="api",
        project_threshold="MEDIUM",
        project_scanners=("bandit",),
    )
    assert resolved.policy_scanners == ("semgrep",)


def test_policy_origin_scanners_do_not_gate_by_default():
    resolved = policy_for_project(
        _policy(additional_scanners=["semgrep"]),
        project_prefix="api",
        project_threshold="MEDIUM",
        project_scanners=(),
    )
    assert resolved.policy_scanners == ("semgrep",)
    assert resolved.policy_scanners_gate is False


def test_policy_origin_scanners_gate_when_the_operator_opts_in():
    resolved = policy_for_project(
        _policy(additional_scanners=["semgrep"], policy_scanners_gate=True),
        project_prefix="api",
        project_threshold="MEDIUM",
        project_scanners=(),
    )
    assert resolved.policy_scanners_gate is True


def test_the_scanner_comparison_ignores_case_and_separator_style():
    """--scanners accepts the alias form, so cdk-nag and cdk_nag are one scanner.

    Treating them as different would run a second copy under default config and
    report its findings as policy-origin duplicates of the project's own.
    """
    resolved = policy_for_project(
        _policy(additional_scanners=["cdk-nag"]),
        project_prefix="api",
        project_threshold="MEDIUM",
        project_scanners=("cdk_nag",),
    )
    assert resolved.policy_scanners == ()


# ---------------------------------------------------------------------------
# 5. Finding the policy file, and refusing to read a project's config as one
# ---------------------------------------------------------------------------


def test_the_policy_file_names_are_disjoint_from_the_project_config_names():
    """Structural guarantee that discovery can never pick up a project config."""
    from automated_security_helper.core.constants import ASH_CONFIG_FILE_NAMES

    assert not set(WORKSPACE_POLICY_FILE_NAMES) & set(ASH_CONFIG_FILE_NAMES)


def test_a_policy_file_beside_the_workspace_file_is_discovered(tmp_path):
    _write(
        tmp_path / ".ash" / "ash-workspace.yaml",
        "workspace:\n  max_severity_threshold: HIGH\n",
    )
    config, source = resolve_workspace_policy(tmp_path)
    assert config.workspace.max_severity_threshold == "HIGH"
    assert source == (tmp_path / ".ash" / "ash-workspace.yaml").resolve()


def test_no_policy_file_at_all_is_not_an_error(tmp_path):
    """Workspace policy is opt-in; Phase 2b behaviour must survive its absence."""
    config, source = resolve_workspace_policy(tmp_path)
    assert config is None
    assert source is None


def test_an_explicit_policy_file_is_used(tmp_path):
    explicit = _write(
        tmp_path / "custom-policy.yaml",
        "workspace:\n  max_severity_threshold: LOW\n",
    )
    config, source = resolve_workspace_policy(tmp_path, explicit=explicit)
    assert config.workspace.max_severity_threshold == "LOW"
    assert source == explicit.resolve()


def test_a_workspace_root_that_is_also_a_project_keeps_both_files_separate(tmp_path):
    """The collision case from the RFC, stated as behaviour.

    .ash/ash.yaml at the workspace root belongs to the root project. Reading it
    as workspace policy would apply one project's threshold to its siblings.
    """
    _write(
        tmp_path / ".ash" / "ash.yaml",
        "global_settings:\n  severity_threshold: CRITICAL\n",
    )
    _write(
        tmp_path / ".ash" / "ash-workspace.yaml",
        "workspace:\n  max_severity_threshold: MEDIUM\n",
    )

    config, source = resolve_workspace_policy(tmp_path)
    assert source.name == "ash-workspace.yaml"
    assert config.workspace.max_severity_threshold == "MEDIUM"


def test_pointing_the_policy_at_a_project_config_is_refused_naming_the_file(tmp_path):
    project_config = _write(
        tmp_path / ".ash" / "ash.yaml",
        "global_settings:\n  severity_threshold: HIGH\n",
    )
    with pytest.raises(WorkspaceDefinitionError) as excinfo:
        resolve_workspace_policy(tmp_path, explicit=project_config)

    message = str(excinfo.value)
    assert "ash.yaml" in message
    assert "ash-workspace" in message


def test_pointing_the_policy_at_a_named_project_config_is_refused(tmp_path):
    """Caught by identity against the project's own config path, not by name.

    An operator may name their policy file anything; what makes this a
    collision is that the file IS a project's config, so a symlink alias to one
    has to be caught too.
    """
    project = tmp_path / "api"
    project_config = _write(project / ".ash" / "ash.yaml", "global_settings: {}\n")
    with pytest.raises(WorkspaceDefinitionError) as excinfo:
        resolve_workspace_policy(
            tmp_path,
            explicit=project_config,
            project_config_paths=(project_config,),
        )
    assert "api" in str(excinfo.value)


def test_two_candidate_policy_files_are_refused_rather_than_ranked(tmp_path):
    """Sort order or mtime would silently pick a different file over time."""
    _write(tmp_path / ".ash" / "ash-workspace.yaml", "workspace: {}\n")
    _write(tmp_path / ".ash" / "ash-workspace.yml", "workspace: {}\n")

    with pytest.raises(WorkspaceDefinitionError) as excinfo:
        resolve_workspace_policy(tmp_path)

    message = str(excinfo.value)
    assert "ash-workspace.yaml" in message
    assert "ash-workspace.yml" in message


def test_a_malformed_policy_file_is_refused(tmp_path):
    _write(tmp_path / ".ash" / "ash-workspace.yaml", "workspace: [this is not a map\n")
    with pytest.raises(WorkspaceDefinitionError):
        resolve_workspace_policy(tmp_path)


def test_an_explicit_policy_file_that_does_not_exist_is_refused(tmp_path):
    """Silently ignoring it would run with no policy while the operator believes
    a ceiling is in force."""
    with pytest.raises(WorkspaceDefinitionError) as excinfo:
        resolve_workspace_policy(tmp_path, explicit=tmp_path / "absent.yaml")
    assert "absent.yaml" in str(excinfo.value)


def test_a_policy_file_with_an_unknown_key_is_refused_naming_the_file(tmp_path):
    path = _write(
        tmp_path / ".ash" / "ash-workspace.yaml",
        "workspace:\n  max_severity_threshhold: HIGH\n",
    )
    with pytest.raises(WorkspaceDefinitionError) as excinfo:
        resolve_workspace_policy(tmp_path)
    assert path.name in str(excinfo.value)


def test_a_json_policy_file_is_read(tmp_path):
    _write(
        tmp_path / ".ash" / "ash-workspace.json",
        json.dumps({"workspace": {"max_severity_threshold": "HIGH"}}),
    )
    config, _ = resolve_workspace_policy(tmp_path)
    assert config.workspace.max_severity_threshold == "HIGH"
