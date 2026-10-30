# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Resolver edges: what the plan records, names and refuses, each one read wrongly
at the base.

* The operator's config was checked without the MCP session's permit gate, so its
  ``extends`` chain was opened ungated before each project's resolution applied
  the gate to the same file.
* The operator-config digest was recorded only for projects with a config of
  their own, so a rewrite of the operator's file between plan and scan was not
  detectable for a project that uses that file alone.
* A plugin scanner section that is a bare ``false`` read as enabled, because
  ``getattr(False, "enabled", True)`` is True.
* A disabled scanner's pin was recorded and compared, so a tool that would not
  run could refuse the workspace. That rule is for the declared scanners only: an
  extra, plugin-provided section is read by a reduced name, so its pin is
  recorded whether or not it is on, and a pair the plan cannot resolve records a
  pin only when every section of it, an off one included, sets the same one.
* The pin of a disabled scanner that a workspace policy then switches on was in
  no comparison, although the scan applies it: the policy is applied after the
  pins are compared.
* A remote client's containment refusal echoed the real path an entry resolved
  to.
* A discovered project config that is the operator's own file (a link to
  ``--config``) was layered over itself, which execution then refused.
* The planner and the scan each decided "a project's own config" by a reading of
  their own, so a file one admitted as the operator's and the other did not (the
  MCP session's copy of the profile, the registered profile, a case-spelled
  link) was layered over itself or left bare, and the project was refused at
  scan time.
* The differing-plugin-modules refusal named modules raw, not by the mask the
  plan carries for exactly that message.
* A decorated display label could equal another project's plain one.
* A project that fell back to ``--config`` recorded it as its config, and the
  policy resolver then treated the operator's file as "a project's own config".
* ``Path.is_file()`` on the ``--config`` path raised a bare ``PermissionError``.
* A ``project_name`` read from the environment was printed as its value.
* A config path that ``Path.resolve`` could not resolve (a link loop raises
  ``RuntimeError`` on 3.10 to 3.12) escaped the UTF-8 path check as a traceback
  instead of a definition error.
"""

import os
from pathlib import Path

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.ash_workspace_config import WorkspacePolicyConfig
from automated_security_helper.config.resolve_config import operator_config_digest
from automated_security_helper.core.exceptions import (
    ASHConfigValidationError,
    WorkspaceDefinitionError,
)
from automated_security_helper.models.workspace import SkippedProjectReason
from automated_security_helper.workspace import resolver
from automated_security_helper.workspace.plan import ProjectPlan
from automated_security_helper.workspace.policy import policy_for_project
from automated_security_helper.workspace.resolver import (
    _apply_workspace_policy,
    _assign_display_labels,
    _disabled_scanner_pins,
    _record_pins_the_policy_turns_on,
    _refuse_config_files_that_are_not_utf8,
    _refuse_missing_default_config,
    _resolve_project_config,
    _scanner_state,
    _unresolved_pins,
    _validate_plugin_modules,
    _validate_scanner_pins,
    resolve_workspace,
)
from automated_security_helper.workspace.workspace_file import WorkspaceDefinition

pytestmark = pytest.mark.unit


def _symlink_or_skip(link, target, target_is_directory=False) -> None:
    try:
        link.symlink_to(target, target_is_directory=target_is_directory)
    except (OSError, NotImplementedError) as exc:  # pragma: no cover - Windows
        pytest.skip(f"symlink creation unavailable on this platform: {exc}")


def _workspace(root: Path, folders, name="dev.code-workspace") -> Path:
    import json

    path = root / name
    path.write_text(
        json.dumps({"folders": [{"path": p} for p in folders]}), encoding="utf-8"
    )
    return path


def _project(root: Path, relative: str, config: str | None = None) -> Path:
    project = root / relative
    project.mkdir(parents=True, exist_ok=True)
    if config is not None:
        (project / ".ash").mkdir(exist_ok=True)
        (project / ".ash" / "ash.yaml").write_text(config, encoding="utf-8")
    return project


def _entry(key: str, label: str | None = None, **fields) -> ProjectPlan:
    values = {
        "key": key,
        "relative_path": key,
        "path": f"/ws/{key}",
        "label": label or key,
        "display_label": label or key,
    }
    values.update(fields)
    return ProjectPlan(**values)


def _definition(root: Path) -> WorkspaceDefinition:
    return WorkspaceDefinition(path=root / "dev.code-workspace", root=root, folders=())


class TestTheOperatorsConfig:
    def test_the_operator_config_check_runs_under_the_callers_gate(
        self, tmp_path, monkeypatch
    ):
        root = tmp_path / "ws"
        root.mkdir()
        _project(root, "api")
        workspace = _workspace(root, ["api"])
        operator = tmp_path / "operator.yaml"
        operator.write_text("project_name: operator\n", encoding="utf-8")
        seen = {}
        original = resolver.check_operator_config

        def recording(*args, **kwargs):
            seen.update(kwargs)
            return original(*args, **kwargs)

        monkeypatch.setattr(resolver, "check_operator_config", recording)

        def permit(path: Path) -> bool:
            return True

        resolve_workspace(workspace, default_config=operator, permit_base=permit)

        assert seen.get("permit_base") is permit

    def test_a_project_without_its_own_config_carries_the_operators_digest(
        self, tmp_path
    ):
        root = tmp_path / "ws"
        root.mkdir()
        _project(root, "api")
        workspace = _workspace(root, ["api"])
        operator = tmp_path / "operator.yaml"
        operator.write_text("project_name: operator\n", encoding="utf-8")

        plan = resolve_workspace(workspace, default_config=operator)

        project = plan.projects[0]
        assert project.operator_config is None
        assert project.operator_config_digest == operator_config_digest(operator)

    def test_the_digest_field_says_whose_file_it_digests(self):
        """Under an MCP session whose client patched the profile, a project with
        no config of its own resolves the session's copy (config_source) while
        the digest is the registered profile's; the description said the digest
        was of config_source's file for every such project."""
        description = ProjectPlan.model_fields["operator_config_digest"].description

        assert "registered profile" in description
        assert "session's copy" in description
        assert "is this project's config_source" not in description

    def test_the_digests_file_is_the_registered_profile_not_the_sessions_copy(
        self, tmp_path, monkeypatch
    ):
        """The digest is taken from ``_operator_config``'s answer, the registered
        profile when there is one; a project with no own config still resolves
        the session's copy, so the two paths differ for it."""
        registered = tmp_path / "registered.yaml"
        registered.write_text("project_name: registered\n", encoding="utf-8")
        copy = tmp_path / "copy.yaml"
        copy.write_text("project_name: copy\n", encoding="utf-8")
        project_dir = tmp_path / "api"
        project_dir.mkdir()
        monkeypatch.setattr(
            resolver, "find_config_file", lambda directory, permit=None: None
        )
        captured = {}

        def fake_resolve_config(**kwargs):
            captured.update(kwargs)
            return AshConfig()

        monkeypatch.setattr(resolver, "resolve_config", fake_resolve_config)
        candidate = resolver._Candidate("api", project_dir, Path("api"), "api")

        _, config_path, overlay = _resolve_project_config(
            candidate, default_config=copy, trusted_config=registered
        )

        assert config_path == copy
        assert overlay is None
        assert captured["trusted_config_path"] == registered
        assert resolver._operator_config(copy, registered) == registered
        assert operator_config_digest(registered) != operator_config_digest(copy)

    def test_a_config_that_is_the_operators_file_is_not_layered_over_itself(
        self, tmp_path, monkeypatch
    ):
        """Execution decides 'own config' by comparing the two files; a plan that
        layered the operator's file over a link to it was refused at scan time."""
        operator = tmp_path / "operator.yaml"
        operator.write_text("project_name: operator\n", encoding="utf-8")
        project_dir = tmp_path / "api"
        project_dir.mkdir()
        monkeypatch.setattr(
            resolver, "find_config_file", lambda directory, permit=None: operator
        )
        captured = {}

        def fake_resolve_config(**kwargs):
            captured.update(kwargs)
            return AshConfig()

        monkeypatch.setattr(resolver, "resolve_config", fake_resolve_config)
        candidate = resolver._Candidate("api", project_dir, Path("api"), "api")

        _, config_path, overlay = _resolve_project_config(
            candidate, default_config=operator
        )

        assert config_path == operator
        assert overlay is None
        assert captured["overlay_config_path"] is None

    def test_a_default_config_that_cannot_be_examined_is_refused_not_a_traceback(
        self, tmp_path, monkeypatch
    ):
        target = tmp_path / "operator.yaml"
        original = Path.is_file

        def denied(self):
            if self == target:
                raise PermissionError(13, "Permission denied", str(self))
            return original(self)

        monkeypatch.setattr(Path, "is_file", denied)

        with pytest.raises(ASHConfigValidationError, match="cannot be examined"):
            _refuse_missing_default_config(target)

    def test_the_operators_file_is_not_a_projects_config_to_the_policy_resolver(
        self, tmp_path, monkeypatch
    ):
        operator = tmp_path / "operator.yaml"
        operator.write_text("project_name: operator\n", encoding="utf-8")
        own = tmp_path / "api" / ".ash" / "ash.yaml"
        own.parent.mkdir(parents=True)
        own.write_text("project_name: api\n", encoding="utf-8")
        seen = {}

        def fake_resolve_workspace_policy(root, **kwargs):
            seen.update(kwargs)
            return None, None

        monkeypatch.setattr(
            resolver, "resolve_workspace_policy", fake_resolve_workspace_policy
        )
        projects = [
            _entry("api", config_source=own.as_posix()),
            _entry("web", config_source=operator.as_posix()),
        ]

        _apply_workspace_policy(
            _definition(tmp_path), projects, None, default_config=operator
        )

        assert seen["project_config_paths"] == [own]

    def test_the_registered_profile_is_not_a_projects_config_to_the_policy_resolver(
        self, tmp_path, monkeypatch
    ):
        """Under the MCP server ``--config`` is the client's copy of the profile
        and ``trusted_config`` the profile as registered: a project whose config
        is the registered file has no config of its own either."""
        client_copy = tmp_path / "client-copy.yaml"
        client_copy.write_text("project_name: copy\n", encoding="utf-8")
        registered = tmp_path / "registered.yaml"
        registered.write_text("project_name: registered\n", encoding="utf-8")
        own = tmp_path / "api" / ".ash" / "ash.yaml"
        own.parent.mkdir(parents=True)
        own.write_text("project_name: api\n", encoding="utf-8")
        seen = {}

        def fake_resolve_workspace_policy(root, **kwargs):
            seen.update(kwargs)
            return None, None

        monkeypatch.setattr(
            resolver, "resolve_workspace_policy", fake_resolve_workspace_policy
        )
        projects = [
            _entry("api", config_source=own.as_posix()),
            _entry("web", config_source=registered.as_posix()),
            _entry("docs", config_source=client_copy.as_posix()),
        ]

        _apply_workspace_policy(
            _definition(tmp_path),
            projects,
            None,
            default_config=client_copy,
            trusted_config=registered,
        )

        assert seen["project_config_paths"] == [own]


class TestOneAnswerForWhetherAConfigIsTheOperators:
    """The planner and the scan both decide "a project's own config" by
    ``config_is_the_operators``; each used a reading of its own before, and a
    file one admitted and the other refused failed the project at scan time."""

    def _candidate(self, tmp_path):
        project_dir = tmp_path / "api"
        project_dir.mkdir()
        return resolver._Candidate("api", project_dir, Path("api"), "api")

    def _plan_config(self, tmp_path, monkeypatch, discovered, **named):
        captured = {}

        def fake_resolve_config(**kwargs):
            captured.update(kwargs)
            return AshConfig()

        monkeypatch.setattr(
            resolver, "find_config_file", lambda directory, permit=None: discovered
        )
        monkeypatch.setattr(resolver, "resolve_config", fake_resolve_config)
        _, config_path, overlay = _resolve_project_config(
            self._candidate(tmp_path), **named
        )
        return captured, config_path, overlay

    def test_a_link_to_the_clients_copy_of_the_profile_is_not_layered(
        self, tmp_path, monkeypatch
    ):
        """A project config that is the session's copy (``default_config``) is
        the project's config alone: the scan reads it as the operator's file and
        expects nothing layered, so a plan that layered the registered profile
        over it was refused at scan time."""
        client_copy = tmp_path / "client-copy.yaml"
        client_copy.write_text("project_name: copy\n", encoding="utf-8")
        registered = tmp_path / "registered.yaml"
        registered.write_text("project_name: registered\n", encoding="utf-8")

        captured, config_path, overlay = self._plan_config(
            tmp_path,
            monkeypatch,
            client_copy,
            default_config=client_copy,
            trusted_config=registered,
        )

        assert config_path == client_copy
        assert overlay is None
        assert captured["overlay_config_path"] is None

    def test_a_link_to_the_registered_profile_is_not_layered_over_itself(
        self, tmp_path, monkeypatch
    ):
        client_copy = tmp_path / "client-copy.yaml"
        client_copy.write_text("project_name: copy\n", encoding="utf-8")
        registered = tmp_path / "registered.yaml"
        registered.write_text("project_name: registered\n", encoding="utf-8")

        _captured, _config_path, overlay = self._plan_config(
            tmp_path,
            monkeypatch,
            registered,
            default_config=client_copy,
            trusted_config=registered,
        )

        assert overlay is None

    def test_a_config_of_the_projects_own_still_gets_the_operators_layered(
        self, tmp_path, monkeypatch
    ):
        """Control: only a file the operator named is exempt."""
        operator = tmp_path / "operator.yaml"
        operator.write_text("project_name: operator\n", encoding="utf-8")
        own = tmp_path / "own.yaml"
        own.write_text("project_name: own\n", encoding="utf-8")

        captured, config_path, overlay = self._plan_config(
            tmp_path, monkeypatch, own, default_config=operator
        )

        assert config_path == own
        assert overlay == operator
        assert captured["overlay_config_path"] == operator

    def test_two_spellings_of_one_file_are_one_file(self, tmp_path, monkeypatch):
        """macOS: ``--config /ops/ash.yaml`` and a link spelled ``/ops/ASH.yaml``.
        The scan compared resolved paths, which keep each spelling."""
        operator = tmp_path / "ash.yaml"
        operator.write_text("project_name: operator\n", encoding="utf-8")
        spelled = tmp_path / "ASH.yaml"
        real = resolver._directory_identity

        def folding(path, cache):
            if path not in cache:
                found = real(path, {})
                cache[path] = (
                    (1, hash(str(path).casefold()) % 1_000_000_007 + 1)
                    if found is not None or path == spelled
                    else None
                )
            return cache[path]

        monkeypatch.setattr(resolver, "_directory_identity", folding)

        assert resolver.config_is_the_operators(spelled, operator) is True

    def test_a_link_is_the_file_it_reaches_on_a_volume_with_no_inodes(
        self, tmp_path, monkeypatch
    ):
        """Identity says nothing on a filesystem that reports ``st_ino == 0``;
        the resolved paths still do, as the scan always read them."""
        operator = tmp_path / "operator.yaml"
        operator.write_text("project_name: operator\n", encoding="utf-8")
        link = tmp_path / "link.yaml"
        _symlink_or_skip(link, operator)
        real_stat = os.stat

        def stat_without_inodes(path, *args, **kwargs):
            result = real_stat(path, *args, **kwargs)
            fields = list(result)
            fields[1] = 0  # st_ino
            return os.stat_result(tuple(fields))

        monkeypatch.setattr(resolver.os, "stat", stat_without_inodes)

        assert resolver.config_is_the_operators(link, operator) is True

    def test_another_file_or_no_file_is_not_the_operators(self, tmp_path):
        operator = tmp_path / "operator.yaml"
        operator.write_text("project_name: operator\n", encoding="utf-8")
        other = tmp_path / "other.yaml"
        other.write_text("project_name: other\n", encoding="utf-8")

        assert resolver.config_is_the_operators(other, operator) is False
        assert resolver.config_is_the_operators(other, None) is False
        assert resolver.config_is_the_operators(None, operator) is False
        assert resolver.config_is_the_operators(other, operator, operator) is False
        assert resolver.config_is_the_operators(operator, None, operator) is True


class TestScannerSections:
    def test_a_bare_false_section_is_off(self, tmp_path):
        root = tmp_path / "ws"
        root.mkdir()
        _project(root, "api", "project_name: api\nscanners:\n  acme: false\n")
        workspace = _workspace(root, ["api"])

        plan = resolve_workspace(workspace)

        assert "acme" not in plan.projects[0].scanners

    @pytest.mark.parametrize(
        "body",
        [False, "off", [], 0],
        ids=["bare-false", "string", "list", "zero"],
    )
    def test_a_section_that_is_no_mapping_is_off_and_left_to_the_policy(self, body):
        """The plan reads a bare scalar or a list as an off section, so a policy
        that requires the scanner lists it as one it adds. Execution switches it
        on there, and must be handed a section it can switch on (a mapping or a
        model): the resolver half of that contract is that such a name is a
        policy scanner, never silently enabled and never dropped."""
        config = AshConfig.model_validate({"scanners": {"acme": body}})

        enabled, pins, _twins = _scanner_state(config)
        resolved = policy_for_project(
            WorkspacePolicyConfig(additional_scanners=["acme"]),
            project_prefix="api",
            project_threshold="MEDIUM",
            project_scanners=enabled,
        )

        assert "acme" not in enabled
        assert "acme" not in pins
        assert list(resolved.policy_scanners) == ["acme"]

    @pytest.mark.parametrize(
        "body",
        [True, {"enabled": True}, {}],
        ids=["bare-true", "mapping-on", "mapping-default"],
    )
    def test_a_section_that_is_on_is_not_added_by_the_policy(self, body):
        """Control for the rows above: an on section is the project's own."""
        config = AshConfig.model_validate({"scanners": {"acme": body}})

        enabled, _pins, _twins = _scanner_state(config)
        resolved = policy_for_project(
            WorkspacePolicyConfig(additional_scanners=["acme"]),
            project_prefix="api",
            project_threshold="MEDIUM",
            project_scanners=enabled,
        )

        assert "acme" in enabled
        assert list(resolved.policy_scanners) == []

    def test_a_disabled_scanners_pin_is_not_recorded(self):
        config = AshConfig.model_validate(
            {
                "scanners": {
                    "bandit": {"enabled": False, "options": {"tool_version": ">=2"}},
                    "semgrep": {"enabled": True, "options": {"tool_version": ">=1"}},
                }
            }
        )

        enabled, pins, _twins = _scanner_state(config)

        assert "bandit" not in enabled
        assert "bandit" not in pins
        assert pins.get("semgrep") == ">=1"

    def test_the_pin_of_a_disabled_scanner_is_held_for_the_policy(self):
        config = AshConfig.model_validate(
            {
                "scanners": {
                    "bandit": {"enabled": False, "options": {"tool_version": ">=2"}},
                    "semgrep": {"enabled": True, "options": {"tool_version": ">=1"}},
                    "detect-secrets": {"enabled": False},
                }
            }
        )

        assert _disabled_scanner_pins(config) == {"bandit": ">=2"}

    def test_a_policy_that_switches_a_scanner_on_records_the_pin_it_keeps(
        self, tmp_path
    ):
        """The policy is applied after the pins are compared, and
        ``_enable_policy_scanners`` leaves ``options.tool_version`` as it was,
        so the scan applies a pin the comparison never saw."""
        api = _entry("api", policy_scanners=["bandit"])
        web = _entry("web", scanner_pins={"bandit": ">=1,<2"})

        recorded = _record_pins_the_policy_turns_on(
            [api, web], {"api": {"bandit": ">=2"}, "web": {}}
        )

        assert recorded is True
        assert api.scanner_pins == {"bandit": ">=2"}
        assert web.scanner_pins == {"bandit": ">=1,<2"}
        with pytest.raises(WorkspaceDefinitionError) as excinfo:
            _validate_scanner_pins(_definition(tmp_path), [api, web])
        message = str(excinfo.value)
        assert "scanner 'bandit'" in message
        assert ">=2" in message
        assert ">=1,<2" in message

    def test_a_pin_the_policy_does_not_switch_on_stays_unrecorded(self):
        api = _entry("api", policy_scanners=["semgrep"])
        skipped = _entry(
            "docs",
            policy_scanners=["bandit"],
            skipped=True,
            skip_reason=SkippedProjectReason.ERROR,
            skip_detail="absent",
        )

        recorded = _record_pins_the_policy_turns_on(
            [api, skipped],
            {"api": {"bandit": ">=2"}, "docs": {"bandit": ">=2"}},
        )

        assert recorded is False
        assert api.scanner_pins == {}
        assert skipped.scanner_pins == {}

    def test_the_policy_names_the_scanner_the_way_an_operator_types_it(self):
        api = _entry("api", policy_scanners=["CDK_Nag"])

        recorded = _record_pins_the_policy_turns_on([api], {"api": {"cdk-nag": ">=2"}})

        assert recorded is True
        assert api.scanner_pins == {"cdk-nag": ">=2"}

    def test_a_workspace_policy_that_requires_a_disabled_scanner_records_its_pin(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.delenv("ASH_CONFIG", raising=False)
        root = tmp_path / "ws"
        root.mkdir()
        _project(root, "api")
        _project(root, "web")
        workspace = _workspace(root, ["api", "web"])
        (root / ".ash").mkdir()
        (root / ".ash" / "ash-workspace.yaml").write_text(
            "workspace:\n  additional_scanners: [bandit]\n", encoding="utf-8"
        )
        operator = tmp_path / "ops" / "ash.yaml"
        operator.parent.mkdir()
        operator.write_text(
            "project_name: operator\nscanners:\n  bandit:\n    enabled: false\n"
            '    options:\n      tool_version: ">=1.8,<2"\n',
            encoding="utf-8",
        )

        plan = resolve_workspace(workspace, default_config=operator)

        for project in plan.projects:
            assert list(project.policy_scanners) == ["bandit"]
            assert project.scanner_pins["bandit"] == ">=1.8,<2"

    def test_an_extra_section_that_is_off_still_records_its_pin(self):
        """The declared-scanner rule above does not reach an extra section.

        ``snykcode`` is no scanner ASH ships, so the plan has no registered name
        for it and the scan may read this section for the reduced name whatever
        a plugin registers. Its pin is recorded whether or not the section is on,
        and the section itself is not listed as enabled.
        """
        config = AshConfig.model_validate(
            {
                "scanners": {
                    "snykcode": {"enabled": False, "options": {"tool_version": ">=2.0"}}
                }
            }
        )

        enabled, pins, _twins = _scanner_state(config)

        assert "snykcode" not in enabled
        assert pins.get("snykcode") == ">=2.0"

    def test_a_pair_with_one_off_unpinned_section_holds_its_version(self):
        """``Snyk_Code`` beside ``snyk-code`` is a pair the plan cannot resolve.

        The off section sets no pin and the on one does, so the pair does not
        agree: no pin is recorded for it, and the one version it has is held for
        the comparison with the other projects' pins. Dropping the off section
        made the pair read as agreeing and recorded a version the scan might not
        apply.
        """
        config = AshConfig.model_validate(
            {
                "scanners": {
                    "Snyk_Code": {"enabled": False},
                    "snyk-code": {
                        "enabled": True,
                        "options": {"tool_version": ">=2.0"},
                    },
                }
            }
        )

        enabled, pins, twins = _scanner_state(config)
        held = _unresolved_pins(config)

        assert twins == {"snykcode": ["Snyk_Code", "snyk-code"]}
        assert "Snyk_Code" not in enabled
        assert "snyk-code" not in enabled
        assert "Snyk_Code" not in pins
        assert "snyk-code" not in pins
        assert [versions.pins for versions in held.values()] == [[">=2.0"]]


class TestWhatARefusalShows:
    def test_a_remote_clients_containment_refusal_names_no_resolved_path(
        self, tmp_path
    ):
        root = tmp_path / "ws"
        root.mkdir()
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        _symlink_or_skip(root / "linked", elsewhere, target_is_directory=True)
        workspace = _workspace(root, ["linked"])

        with pytest.raises(WorkspaceDefinitionError) as excinfo:
            resolve_workspace(workspace, remote_client=True)

        message = str(excinfo.value)
        assert "'linked' is refused (symlink)" in message
        assert "not shown" in message
        assert "real directories" not in message

    def test_the_plugin_modules_refusal_names_a_module_by_its_mask(self, tmp_path):
        projects = [
            _entry(
                "api",
                ash_plugin_modules=["secret.module"],
                plugin_module_names={"secret.module": "<masked module>"},
            ),
            _entry("web"),
        ]

        with pytest.raises(WorkspaceDefinitionError) as excinfo:
            _validate_plugin_modules(_definition(tmp_path), projects)

        message = str(excinfo.value)
        assert "<masked module>" in message
        assert "secret.module" not in message


class TestDisplayLabels:
    def test_a_decorated_label_does_not_collide_with_a_plain_one(self):
        projects = [
            _entry("web", label="svc (api)"),
            _entry("api", label="svc"),
            _entry("api2", label="svc"),
        ]

        _assign_display_labels(projects)

        shown = [project.display_label for project in projects]
        assert len(set(shown)) == 3
        assert shown[0] == "svc (api) (web)"
        assert shown[1:] == ["svc (api)", "svc (api2)"]

    def test_a_label_read_from_the_environment_is_shown_by_its_mask(
        self, tmp_path, monkeypatch
    ):
        canary = "canary-project-name-q7"
        monkeypatch.setenv("ASH_LABEL_CANARY", canary)
        root = tmp_path / "ws"
        root.mkdir()
        _project(root, "api", "project_name: !ENV ${ASH_LABEL_CANARY}\n")
        workspace = _workspace(root, ["api"])

        plan = resolve_workspace(workspace)

        project = plan.projects[0]
        assert canary not in project.label
        assert canary not in project.display_label
        assert canary not in plan.render()


class TestConfigPathsThatCannotBeResolved:
    """``Path.resolve`` raising anything but ``ValueError`` escaped the check.

    A real link loop raises ``RuntimeError`` only on 3.10 to 3.12 (3.13 returns
    the path unresolved), so the loop is faked: the check must turn the error
    into a definition error on every interpreter, never let it through.
    """

    @pytest.mark.parametrize(
        "raised",
        [RuntimeError("Symlink loop from 'loop'"), OSError(5, "Input/output error")],
        ids=["link-loop", "unreadable-chain"],
    )
    def test_an_unresolvable_default_config_is_a_definition_error(
        self, tmp_path, monkeypatch, raised
    ):
        given = tmp_path / "loop" / "ash.yaml"

        def refuse(self, *args, **kwargs):
            raise raised

        monkeypatch.setattr(Path, "resolve", refuse)

        with pytest.raises(WorkspaceDefinitionError) as excinfo:
            _refuse_config_files_that_are_not_utf8(None, given)

        message = str(excinfo.value)
        assert "the default config, for a project that declares none" in message
        assert type(raised).__name__ in message
        assert "ash.yaml" in message
        assert excinfo.value.__cause__ is raised

    def test_a_resolvable_config_is_still_accepted(self, tmp_path):
        given = tmp_path / "ash.yaml"
        given.write_text("project_name: ok\n", encoding="utf-8")

        _refuse_config_files_that_are_not_utf8(given, None, given)
