# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Edges of reading a policy file and pushing it down, each one a refusal or a
count the base got wrong.

Reading: a JSON policy with a byte order mark was refused while a JSON project
config with one loads; the format came from the resolved target's suffix rather
than the named path's; a document nested past the recursion limit escaped as a
traceback; a symlink loop raised ``RuntimeError`` on 3.10-3.12; an unsearchable
parent raised a bare ``PermissionError``; the by-name project-config check read
the link's name and not the target's; and the explicit path's existence was told
before the permit gate judged the file it reaches, so the two refusals said
whether a file outside the permitted base exists.

Push-down: two spellings of one scanner in ``additional_scanners`` were carried
twice; ``threshold_tightened`` read a declared ``""`` under no ceiling as
tightened; the pattern of a delivered policy was quoted in its refusal; and the
ceiling disclosure counted a padded ``issue_severity`` as level-only and counted
findings of a non-gating policy scanner the gate never judged.
"""

import json
import os
from pathlib import Path

import pytest

from automated_security_helper.config.ash_workspace_config import (
    WorkspacePolicyConfig,
)
from automated_security_helper.core.constants import ASH_CONFIG_FILE_NAMES
from automated_security_helper.core.exceptions import (
    ASHConfigInputNotPermittedError,
    WorkspaceDefinitionError,
)
from automated_security_helper.models.core import AshSuppression
from automated_security_helper.workspace.policy import (
    ceiling_unreachable_counts,
    discover_workspace_policy_file,
    load_workspace_policy,
    named_workspace_policy_path,
    policy_for_project,
    resolve_workspace_policy,
)

pytestmark = pytest.mark.unit

POLICY_YAML = "workspace:\n  max_severity_threshold: HIGH\n"
POLICY_JSON = json.dumps({"workspace": {"max_severity_threshold": "HIGH"}})


def _symlink_or_skip(link: Path, target, target_is_directory=False) -> None:
    try:
        link.symlink_to(target, target_is_directory=target_is_directory)
    except (OSError, NotImplementedError) as exc:  # pragma: no cover - Windows
        pytest.skip(f"symlink creation unavailable on this platform: {exc}")


def _policy(**fields) -> WorkspacePolicyConfig:
    return WorkspacePolicyConfig(**fields)


class TestReadingThePolicyFile:
    def test_a_json_policy_with_a_byte_order_mark_loads(self, tmp_path):
        """The JSON project-config reader decodes utf-8-sig; so does this one."""
        path = tmp_path / ".ash-workspace.json"
        path.write_text(chr(0xFEFF) + POLICY_JSON, encoding="utf-8")

        policy = load_workspace_policy(path)

        assert policy.workspace.max_severity_threshold == "HIGH"

    def test_the_format_is_the_named_paths_suffix(self, tmp_path):
        """A ``.yaml`` name that links to a ``.json`` file is read as YAML."""
        target = tmp_path / "data.json"
        target.write_text(POLICY_YAML, encoding="utf-8")
        link = tmp_path / "pol.yaml"
        _symlink_or_skip(link, target)

        policy = load_workspace_policy(link)

        assert policy.workspace.max_severity_threshold == "HIGH"

    def test_a_document_nested_past_the_recursion_limit_is_refused(self, tmp_path):
        path = tmp_path / ".ash-workspace.json"
        path.write_text("[" * 50000 + "]" * 50000, encoding="utf-8")

        with pytest.raises(WorkspaceDefinitionError, match="could not be parsed"):
            load_workspace_policy(path)

    def test_a_symlink_loop_is_refused_not_a_runtime_error(self, tmp_path):
        loop = tmp_path / "pol.yaml"
        _symlink_or_skip(loop, loop)

        with pytest.raises(WorkspaceDefinitionError):
            load_workspace_policy(loop)

    def test_an_unsearchable_parent_is_refused_not_a_traceback(self, tmp_path):
        """Path.exists() raised a bare PermissionError on 3.10-3.13 and read the
        file as absent on 3.14; os.stat with its error kept does neither."""
        ash_dir = tmp_path / ".ash"
        ash_dir.mkdir()
        path = ash_dir / "ash-workspace.yaml"
        path.write_text(POLICY_YAML, encoding="utf-8")
        ash_dir.chmod(0o000)
        try:
            if os.access(path, os.R_OK):  # pragma: no cover - root
                pytest.skip("running as a user that ignores directory permissions")
            with pytest.raises(WorkspaceDefinitionError, match="could not be examined"):
                load_workspace_policy(path)
            with pytest.raises(WorkspaceDefinitionError, match="could not be examined"):
                named_workspace_policy_path(tmp_path)
        finally:
            ash_dir.chmod(0o755)

    def test_a_link_to_a_project_config_is_refused_by_the_targets_name(self, tmp_path):
        """The root project's config is in no project list, so only the name
        catches it; the base read the link's name and let the config through."""
        config = tmp_path / ASH_CONFIG_FILE_NAMES[1]
        config.write_text(POLICY_YAML, encoding="utf-8")
        link = tmp_path / "pol.yaml"
        _symlink_or_skip(link, config)

        with pytest.raises(WorkspaceDefinitionError, match="named like an ASH"):
            resolve_workspace_policy(tmp_path, explicit=link)

    def test_the_permit_gate_judges_the_target_before_existence_is_told(self, tmp_path):
        """A link inside the permitted root to a missing file outside it was
        told 'does not exist', while a present one was refused by the gate: the
        pair said whether the outside file exists."""
        root = tmp_path / "ws"
        root.mkdir()
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        link = root / "pol.yaml"
        _symlink_or_skip(link, elsewhere / "missing.yaml")

        def permit(path: Path) -> bool:
            return path == root or root in path.parents

        with pytest.raises(ASHConfigInputNotPermittedError):
            resolve_workspace_policy(root, explicit=link, permit_base=permit)

    @pytest.mark.parametrize("target_kind", ["missing", "directory", "file"])
    def test_discovery_judges_the_target_before_its_kind_is_read(
        self, tmp_path, target_kind
    ):
        """Discovery gated the link's own name and then read what it reaches:
        a missing target said 'not there', a directory 'is a directory', a file
        was refused by the resolver's gate. Three answers about a target outside
        the permitted root, the probe the explicit-path reorder closed. One
        refusal now, whatever the target is."""
        root = tmp_path / "ws"
        root.mkdir()
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        target = elsewhere / "target"
        if target_kind == "directory":
            target.mkdir()
        elif target_kind == "file":
            target.write_text(POLICY_YAML, encoding="utf-8")
        _symlink_or_skip(root / "ash-workspace.yaml", target)

        def permit(path: Path) -> bool:
            return path == root or root in path.parents

        with pytest.raises(WorkspaceDefinitionError) as excinfo:
            discover_workspace_policy_file(root, permit=permit)

        message = str(excinfo.value)
        assert "outside the directories" in message
        assert "ash-workspace.yaml" in message
        for told in ("not there", "is a directory, not a file", "not a regular file"):
            assert told not in message, message
        assert isinstance(excinfo.value.__cause__, ASHConfigInputNotPermittedError)

    def test_an_explicit_path_outside_the_root_is_named_as_given(self, tmp_path):
        root = tmp_path / "ws"
        root.mkdir()
        outside = tmp_path / "pol.yaml"
        outside.write_text(POLICY_YAML, encoding="utf-8")

        with pytest.raises(WorkspaceDefinitionError) as excinfo:
            resolve_workspace_policy(
                root, explicit=outside, permit_base=lambda p: False
            )

        message = str(excinfo.value)
        assert outside.as_posix() in message
        assert "' in '" not in message


class TestPushDown:
    def test_two_spellings_of_one_scanner_are_carried_once(self):
        resolved = policy_for_project(
            _policy(additional_scanners=["cdk-nag", "cdk_nag", "bandit", "bandit"]),
            project_prefix="api",
            project_threshold=None,
            project_scanners=[],
        )
        assert resolved.policy_scanners == ("cdk-nag", "bandit")

    def test_a_declared_empty_threshold_under_no_ceiling_is_not_tightened(self):
        resolved = policy_for_project(
            _policy(),
            project_prefix="api",
            project_threshold="",
            project_scanners=[],
        )
        assert resolved.threshold_tightened is False

    def test_a_declared_empty_threshold_under_a_ceiling_is_tightened(self):
        resolved = policy_for_project(
            _policy(max_severity_threshold="HIGH"),
            project_prefix="api",
            project_threshold="",
            project_scanners=[],
        )
        assert resolved.threshold_tightened is True
        assert resolved.effective_threshold == "HIGH"

    def test_a_delivered_policys_refused_pattern_is_not_quoted(self):
        """``*/sub/*.py`` has no sound rewrite (the two glob semantics); a
        client's file is refused by the entry's position, not its text."""
        policy = _policy(
            suppressions=[AshSuppression(path="*/sub/*.py", reason="delivered")]
        )

        with pytest.raises(WorkspaceDefinitionError) as excinfo:
            policy_for_project(
                policy,
                project_prefix="api",
                project_threshold=None,
                project_scanners=[],
                quote_values=False,
            )

        message = str(excinfo.value)
        assert "*/sub/*.py" not in message
        assert "suppression entry 1" in message
        assert "not shown" in message

    def test_the_operators_own_refused_pattern_is_still_quoted(self):
        policy = _policy(
            suppressions=[AshSuppression(path="*/sub/*.py", reason="mine")]
        )
        with pytest.raises(WorkspaceDefinitionError, match=r"\*/sub/\*\.py"):
            policy_for_project(
                policy,
                project_prefix="api",
                project_threshold=None,
                project_scanners=[],
            )

    @pytest.mark.parametrize("quote_values", [True, False], ids=["quoted", "unquoted"])
    @pytest.mark.parametrize("field", ["path", "package_path"])
    def test_a_refusal_shows_the_project_prefix_as_the_policy_records_it(
        self, field, quote_values
    ):
        """A prefix written with a backslash is one project, ``apps/api``. On
        POSIX ``Path(...).as_posix()`` keeps the backslash, so a refusal that
        showed the prefix that way spelled the project one way while the rest of
        the policy (and the pattern converter's own message) spelled it another.
        ``apps/*/x.py`` has a wildcard inside the project path, so it has no
        sound rewrite and is refused, for the entry's path and for its
        package_path alike."""
        if field == "path":
            entry = AshSuppression(path="apps/*/x.py", reason="mine")
        else:
            entry = AshSuppression(
                path="**/*.js", reason="mine", package_path="apps/*/x.py"
            )

        with pytest.raises(WorkspaceDefinitionError) as excinfo:
            policy_for_project(
                _policy(suppressions=[entry]),
                project_prefix="apps\\api",
                project_threshold=None,
                project_scanners=[],
                quote_values=quote_values,
            )

        message = str(excinfo.value)
        assert "cannot be applied to project 'apps/api'" in message
        assert "apps\\api" not in message


class TestTheCeilingDisclosure:
    @staticmethod
    def _result(scanner: str, **properties) -> dict:
        return {
            "ruleId": "R1",
            "level": "error",
            "properties": {"scanner_name": scanner, **properties},
        }

    def test_a_padded_severity_is_read_as_the_gate_reads_it(self):
        """``severity_ladder`` strips before it compares; a finding whose
        severity the gate honors is not a level-only finding."""
        counts = ceiling_unreachable_counts(
            [self._result("bandit", issue_severity=" HIGH ")],
            declared_threshold="CRITICAL",
            effective_threshold="LOW",
        )
        assert counts == {}

    def test_a_non_gating_policy_scanners_findings_are_not_counted(self):
        counts = ceiling_unreachable_counts(
            [self._result("checkov"), self._result("trivy"), self._result("Trivy")],
            declared_threshold="CRITICAL",
            effective_threshold="LOW",
            non_gating_scanners=["trivy"],
        )
        assert counts == {"checkov": 1}

    def test_without_the_set_every_level_only_finding_still_counts(self):
        counts = ceiling_unreachable_counts(
            [self._result("checkov"), self._result("trivy")],
            declared_threshold="CRITICAL",
            effective_threshold="LOW",
        )
        assert counts == {"checkov": 1, "trivy": 1}
