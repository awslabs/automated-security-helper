# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""`extends` and `patch`: one config built on others (#289).

Rules under test (documented in config/config_sources.py):

* bases merge left to right, the extending file wins over all of them;
* mappings merge key by key, lists and scalars replace;
* `patch` (RFC 6902 add/remove/replace/test) runs after the merge;
* a cycle, a chain past its bounds, a missing base, or a base outside the
  confinement root is an error, never a silent fallback to the defaults;
* URLs are refused, nothing is fetched.
"""

import os
import textwrap
from pathlib import Path

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.core.constants import (
    ASH_CONFIG_EXTENDS_MAX_DEPTH,
    ASH_CONFIG_EXTENDS_MAX_FILES,
)
from automated_security_helper.core.exceptions import ASHConfigValidationError


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(text).lstrip(), encoding="utf-8")
    return path


def _suppression(rule: str) -> str:
    return f"""
    - rule_id: {rule}
      path: "src/{rule}.py"
      reason: "reviewed {rule}"
"""


def _load(tmp_path: Path) -> AshConfig:
    return resolve_config(source_dir=tmp_path)


class TestSingleBase:
    def test_child_inherits_base_and_wins_where_both_set(self, tmp_path):
        _write(
            tmp_path / "shared" / "base.yaml",
            """
            project_name: base-name
            fail_on_findings: false
            global_settings:
              severity_threshold: LOW
            """,
        )
        _write(
            tmp_path / ".ash.yaml",
            """
            extends: shared/base.yaml
            project_name: child-name
            """,
        )
        config = _load(tmp_path)
        assert config.project_name == "child-name"
        assert config.fail_on_findings is False
        assert config.global_settings.severity_threshold == "LOW"

    def test_base_path_is_relative_to_the_extending_file(self, tmp_path):
        _write(tmp_path / ".ash" / "base.yaml", "project_name: from-dot-ash-base\n")
        _write(tmp_path / ".ash" / ".ash.yaml", "extends: base.yaml\n")
        assert _load(tmp_path).project_name == "from-dot-ash-base"

    def test_dotdot_that_stays_inside_the_root_is_allowed(self, tmp_path):
        _write(tmp_path / "org" / "base.yaml", "project_name: up-and-over\n")
        _write(tmp_path / ".ash" / ".ash.yaml", "extends: ../org/base.yaml\n")
        assert _load(tmp_path).project_name == "up-and-over"

    def test_maps_merge_recursively(self, tmp_path):
        _write(
            tmp_path / "base.yaml",
            """
            project_name: p
            scanners:
              bandit:
                enabled: false
                options:
                  probe_from_base: kept
            """,
        )
        _write(
            tmp_path / ".ash.yaml",
            """
            extends: base.yaml
            scanners:
              bandit:
                options:
                  probe_from_child: added
              checkov:
                enabled: false
            """,
        )
        config = _load(tmp_path)
        bandit = config.scanners.bandit.model_dump()
        assert bandit["enabled"] is False
        assert bandit["options"]["probe_from_base"] == "kept"
        assert bandit["options"]["probe_from_child"] == "added"
        assert config.scanners.checkov.enabled is False

    def test_lists_are_replaced_not_concatenated(self, tmp_path):
        _write(
            tmp_path / "base.yaml",
            "project_name: p\nglobal_settings:\n  severity_threshold: LOW\n"
            "  suppressions:" + _suppression("B101"),
        )
        _write(
            tmp_path / ".ash.yaml",
            "extends: base.yaml\nglobal_settings:\n  suppressions:"
            + _suppression("B602"),
        )
        config = _load(tmp_path)
        rules = [s.rule_id for s in config.global_settings.suppressions]
        assert rules == ["B602"]
        # The sibling key in the same mapping still comes from the base.
        assert config.global_settings.severity_threshold == "LOW"

    def test_child_scalar_replaces_base_mapping_value(self, tmp_path):
        _write(
            tmp_path / "base.yaml",
            "project_name: from-base\nfail_on_findings: true\n",
        )
        _write(tmp_path / ".ash.yaml", "extends: base.yaml\nfail_on_findings: false\n")
        config = _load(tmp_path)
        assert config.fail_on_findings is False
        assert config.project_name == "from-base"

    def test_the_extending_file_dump_has_no_directives(self, tmp_path):
        _write(tmp_path / "base.yaml", "project_name: p\n")
        _write(tmp_path / ".ash.yaml", "extends: base.yaml\n")
        config = _load(tmp_path)
        assert config.extends is None and config.patch is None
        dumped = config.model_dump(by_alias=True)
        assert "extends" not in dumped and "patch" not in dumped


class TestChainsAndMultipleBases:
    def test_three_level_chain(self, tmp_path):
        _write(
            tmp_path / "c.yaml",
            "project_name: from-c\nfail_on_findings: false\n"
            "global_settings:\n  severity_threshold: LOW\n",
        )
        _write(
            tmp_path / "b.yaml",
            "extends: c.yaml\nproject_name: from-b\n"
            "global_settings:\n  severity_threshold: MEDIUM\n",
        )
        _write(tmp_path / ".ash.yaml", "extends: b.yaml\nproject_name: from-a\n")
        config = _load(tmp_path)
        assert config.project_name == "from-a"
        assert config.global_settings.severity_threshold == "MEDIUM"
        assert config.fail_on_findings is False

    def test_multiple_bases_later_wins_and_child_wins_over_all(self, tmp_path):
        _write(
            tmp_path / "first.yaml",
            "project_name: first\nfail_on_findings: false\n"
            "global_settings:\n  severity_threshold: LOW\n",
        )
        _write(
            tmp_path / "second.yaml",
            "project_name: second\nglobal_settings:\n  severity_threshold: HIGH\n",
        )
        _write(
            tmp_path / ".ash.yaml",
            "extends: [first.yaml, second.yaml]\nproject_name: child\n",
        )
        config = _load(tmp_path)
        assert config.project_name == "child"
        assert config.global_settings.severity_threshold == "HIGH"
        assert config.fail_on_findings is False

    def test_diamond_is_not_a_cycle(self, tmp_path):
        _write(tmp_path / "root.yaml", "project_name: shared-root\n")
        _write(tmp_path / "left.yaml", "extends: root.yaml\nfail_on_findings: false\n")
        _write(tmp_path / "right.yaml", "extends: root.yaml\n")
        _write(tmp_path / ".ash.yaml", "extends: [left.yaml, right.yaml]\n")
        config = _load(tmp_path)
        assert config.project_name == "shared-root"
        assert config.fail_on_findings is False

    def test_chain_at_the_depth_limit_loads(self, tmp_path):
        last = ASH_CONFIG_EXTENDS_MAX_DEPTH
        _write(tmp_path / f"level{last}.yaml", "project_name: deepest\n")
        for i in range(last - 1, 0, -1):
            _write(tmp_path / f"level{i}.yaml", f"extends: level{i + 1}.yaml\n")
        _write(tmp_path / ".ash.yaml", "extends: level1.yaml\n")
        assert _load(tmp_path).project_name == "deepest"

    def test_chain_past_the_depth_limit_fails_with_the_chain(self, tmp_path):
        last = ASH_CONFIG_EXTENDS_MAX_DEPTH + 1
        _write(tmp_path / f"level{last}.yaml", "project_name: too-deep\n")
        for i in range(last - 1, 0, -1):
            _write(tmp_path / f"level{i}.yaml", f"extends: level{i + 1}.yaml\n")
        _write(tmp_path / ".ash.yaml", "extends: level1.yaml\n")
        with pytest.raises(ASHConfigValidationError, match="deeper than") as excinfo:
            _load(tmp_path)
        assert "level1.yaml -> " in str(excinfo.value)

    def test_fan_out_past_the_file_limit_fails(self, tmp_path):
        _write(tmp_path / "base.yaml", "project_name: p\n")
        refs = ", ".join(["base.yaml"] * ASH_CONFIG_EXTENDS_MAX_FILES)
        _write(tmp_path / ".ash.yaml", f"extends: [{refs}]\n")
        with pytest.raises(ASHConfigValidationError, match="more than"):
            _load(tmp_path)


class TestCycles:
    def test_direct_self_reference(self, tmp_path):
        _write(tmp_path / ".ash.yaml", "extends: .ash.yaml\nproject_name: p\n")
        with pytest.raises(ASHConfigValidationError, match="cycle"):
            _load(tmp_path)

    def test_transitive_cycle_reports_the_chain(self, tmp_path):
        _write(tmp_path / "b.yaml", "extends: c.yaml\n")
        _write(tmp_path / "c.yaml", "extends: b.yaml\n")
        _write(tmp_path / ".ash.yaml", "extends: b.yaml\n")
        with pytest.raises(ASHConfigValidationError) as excinfo:
            _load(tmp_path)
        message = str(excinfo.value)
        assert "cycle" in message
        chain = message.split("cycle: ", 1)[1]
        names = [Path(part.strip()).name for part in chain.split("->")]
        assert names == [".ash.yaml", "b.yaml", "c.yaml", "b.yaml"]


class TestFailuresAreNotSilent:
    def test_missing_base_is_an_error_not_the_default_config(self, tmp_path):
        _write(tmp_path / ".ash.yaml", "extends: nowhere.yaml\nproject_name: p\n")
        with pytest.raises(ASHConfigValidationError, match="nowhere.yaml"):
            _load(tmp_path)

    def test_unparseable_base_is_an_error(self, tmp_path):
        _write(tmp_path / "base.yaml", "project_name: [unclosed\n")
        _write(tmp_path / ".ash.yaml", "extends: base.yaml\n")
        with pytest.raises(ASHConfigValidationError, match="could not be read"):
            _load(tmp_path)

    def test_base_that_is_not_a_mapping_is_an_error(self, tmp_path):
        _write(tmp_path / "base.yaml", "- just\n- a list\n")
        _write(tmp_path / ".ash.yaml", "extends: base.yaml\n")
        with pytest.raises(ASHConfigValidationError, match="must be a mapping"):
            _load(tmp_path)

    @pytest.mark.parametrize("value", ["42", "[base.yaml, 7]", "''", "{a: b}"])
    def test_malformed_extends_value_is_an_error(self, tmp_path, value):
        _write(tmp_path / "base.yaml", "project_name: p\n")
        _write(tmp_path / ".ash.yaml", f"extends: {value}\n")
        with pytest.raises(ASHConfigValidationError, match="must be a path"):
            _load(tmp_path)

    def test_validating_unresolved_directives_directly_is_refused(self):
        with pytest.raises(ValueError, match="resolved when a config file is loaded"):
            AshConfig.model_validate({"project_name": "p", "extends": "base.yaml"})


class TestConfinement:
    def test_dotdot_escaping_the_root_is_refused(self, tmp_path):
        outside = tmp_path / "outside"
        repo = tmp_path / "repo"
        _write(outside / "base.yaml", "project_name: escaped\n")
        _write(repo / ".ash.yaml", "extends: ../outside/base.yaml\n")
        with pytest.raises(ASHConfigValidationError, match="outside the directory"):
            resolve_config(source_dir=repo)

    def test_absolute_path_outside_the_root_is_refused(self, tmp_path):
        outside = _write(tmp_path / "outside" / "base.yaml", "project_name: escaped\n")
        repo = tmp_path / "repo"
        _write(repo / ".ash.yaml", f"extends: {outside.as_posix()}\n")
        with pytest.raises(ASHConfigValidationError, match="outside the directory"):
            resolve_config(source_dir=repo)

    def test_absolute_path_inside_the_root_is_allowed(self, tmp_path):
        base = _write(tmp_path / "shared" / "base.yaml", "project_name: absolute\n")
        _write(tmp_path / ".ash.yaml", f"extends: {base.as_posix()}\n")
        assert _load(tmp_path).project_name == "absolute"

    @pytest.mark.skipif(not hasattr(os, "symlink"), reason="needs symlinks")
    def test_symlink_pointing_outside_the_root_is_refused(self, tmp_path):
        outside = _write(tmp_path / "outside" / "base.yaml", "project_name: escaped\n")
        repo = tmp_path / "repo"
        repo.mkdir()
        try:
            (repo / "base.yaml").symlink_to(outside)
        except OSError:
            pytest.skip("symlinks are not available")
        _write(repo / ".ash.yaml", "extends: base.yaml\n")
        with pytest.raises(ASHConfigValidationError, match="through a symlink"):
            resolve_config(source_dir=repo)

    @pytest.mark.skipif(not hasattr(os, "symlink"), reason="needs symlinks")
    def test_symlinked_directory_pointing_outside_is_refused(self, tmp_path):
        _write(tmp_path / "outside" / "base.yaml", "project_name: escaped\n")
        repo = tmp_path / "repo"
        repo.mkdir()
        try:
            (repo / "shared").symlink_to(tmp_path / "outside", target_is_directory=True)
        except OSError:
            pytest.skip("symlinks are not available")
        _write(repo / ".ash.yaml", "extends: shared/base.yaml\n")
        with pytest.raises(ASHConfigValidationError, match="through a symlink"):
            resolve_config(source_dir=repo)

    @pytest.mark.skipif(not hasattr(os, "symlink"), reason="needs symlinks")
    def test_symlink_staying_inside_the_root_is_allowed(self, tmp_path):
        real = _write(tmp_path / "configs" / "real-base.yaml", "project_name: linked\n")
        try:
            (tmp_path / "base.yaml").symlink_to(real)
        except OSError:
            pytest.skip("symlinks are not available")
        _write(tmp_path / ".ash.yaml", "extends: base.yaml\n")
        assert _load(tmp_path).project_name == "linked"

    @pytest.mark.parametrize(
        "ref",
        [
            "https://example.com/ash-base.yaml",
            "http://127.0.0.1:9/base.yaml",
            "file:///etc/ash/base.yaml",
            "s3://bucket/base.yaml",
        ],
    )
    def test_urls_are_refused_and_not_fetched(self, tmp_path, monkeypatch, ref):
        import socket
        import urllib.request

        def _no_network(*args, **kwargs):
            raise AssertionError("extends must not open a connection")

        monkeypatch.setattr(socket, "create_connection", _no_network)
        monkeypatch.setattr(urllib.request, "urlopen", _no_network)
        _write(tmp_path / ".ash.yaml", f'extends: "{ref}"\n')
        with pytest.raises(ASHConfigValidationError, match="does not fetch remote"):
            _load(tmp_path)

    def test_explicit_config_outside_source_dir_is_confined_to_its_own_dir(
        self, tmp_path
    ):
        repo = tmp_path / "repo"
        repo.mkdir()
        _write(tmp_path / "ops" / "base.yaml", "project_name: ops-base\n")
        org = _write(tmp_path / "ops" / "org.yaml", "extends: base.yaml\n")
        config = resolve_config(config_path=org, source_dir=repo)
        assert config.project_name == "ops-base"

        _write(tmp_path / "secrets.yaml", "project_name: sibling\n")
        _write(tmp_path / "ops" / "org.yaml", "extends: ../secrets.yaml\n")
        with pytest.raises(ASHConfigValidationError, match="outside the directory"):
            resolve_config(config_path=org, source_dir=repo)


class TestPatch:
    def test_add_appends_to_a_base_list(self, tmp_path):
        _write(
            tmp_path / "base.yaml",
            "project_name: p\nglobal_settings:\n  suppressions:" + _suppression("B101"),
        )
        _write(
            tmp_path / ".ash.yaml",
            """
            extends: base.yaml
            patch:
              - op: add
                path: /global_settings/suppressions/-
                value:
                  rule_id: B602
                  path: src/B602.py
                  reason: reviewed B602
            """,
        )
        rules = [s.rule_id for s in _load(tmp_path).global_settings.suppressions]
        assert rules == ["B101", "B602"]

    def test_replace_and_remove(self, tmp_path):
        _write(
            tmp_path / "base.yaml",
            """
            project_name: p
            fail_on_findings: false
            global_settings:
              severity_threshold: LOW
            """,
        )
        _write(
            tmp_path / ".ash.yaml",
            """
            extends: base.yaml
            patch:
              - {op: replace, path: /global_settings/severity_threshold, value: CRITICAL}
              - {op: remove, path: /fail_on_findings}
            """,
        )
        config = _load(tmp_path)
        assert config.global_settings.severity_threshold == "CRITICAL"
        # Removed from the merged document, so the model default applies.
        assert config.fail_on_findings is True

    def test_patch_runs_after_the_files_own_keys(self, tmp_path):
        _write(tmp_path / "base.yaml", "project_name: base\n")
        _write(
            tmp_path / ".ash.yaml",
            """
            extends: base.yaml
            project_name: own-key
            patch:
              - {op: replace, path: /project_name, value: patched}
            """,
        )
        assert _load(tmp_path).project_name == "patched"

    def test_patch_without_extends_applies_to_the_file(self, tmp_path):
        _write(
            tmp_path / ".ash.yaml",
            """
            project_name: p
            patch:
              - {op: add, path: /fail_on_findings, value: false}
            """,
        )
        assert _load(tmp_path).fail_on_findings is False

    def test_failed_test_op_aborts(self, tmp_path):
        _write(tmp_path / "base.yaml", "project_name: base\n")
        _write(
            tmp_path / ".ash.yaml",
            """
            extends: base.yaml
            patch:
              - {op: test, path: /project_name, value: not-the-base}
            """,
        )
        with pytest.raises(ASHConfigValidationError, match="entry 0"):
            _load(tmp_path)

    @pytest.mark.parametrize("op", ["move", "copy", "frobnicate"])
    def test_ops_outside_the_allowed_set_are_refused(self, tmp_path, op):
        _write(
            tmp_path / ".ash.yaml",
            f"""
            project_name: p
            patch:
              - {{op: {op}, from: /project_name, path: /fail_on_findings}}
            """,
        )
        with pytest.raises(ASHConfigValidationError, match="allowed ops"):
            _load(tmp_path)

    def test_patch_must_be_a_list(self, tmp_path):
        _write(tmp_path / ".ash.yaml", "project_name: p\npatch: {op: add}\n")
        with pytest.raises(ASHConfigValidationError, match="must be a list"):
            _load(tmp_path)

    def test_remove_of_a_missing_path_fails(self, tmp_path):
        _write(tmp_path / "base.yaml", "project_name: p\n")
        _write(
            tmp_path / ".ash.yaml",
            "extends: base.yaml\npatch:\n  - {op: remove, path: /no_such_key}\n",
        )
        with pytest.raises(ASHConfigValidationError, match="failed"):
            _load(tmp_path)


class TestAliasSpellings:
    """#691: `cdk-nag` (alias) and `cdk_nag` (field name) are one section."""

    def test_child_field_name_overrides_base_alias(self, tmp_path):
        _write(
            tmp_path / "base.yaml",
            """
            project_name: p
            scanners:
              cdk-nag:
                enabled: false
                options:
                  probe_from_base: kept
            """,
        )
        _write(
            tmp_path / ".ash.yaml",
            """
            extends: base.yaml
            scanners:
              cdk_nag:
                enabled: true
            """,
        )
        config = _load(tmp_path)
        cdk_nag = config.scanners.cdk_nag.model_dump()
        assert cdk_nag["enabled"] is True
        assert cdk_nag["options"]["probe_from_base"] == "kept"
        assert not (config.scanners.__pydantic_extra__ or {})

    def test_child_alias_overrides_base_field_name(self, tmp_path):
        _write(
            tmp_path / "base.yaml",
            """
            project_name: p
            scanners:
              cdk_nag:
                enabled: true
                options:
                  probe_from_base: kept
            """,
        )
        _write(
            tmp_path / ".ash.yaml",
            """
            extends: base.yaml
            scanners:
              cdk-nag:
                enabled: false
            """,
        )
        cdk_nag = _load(tmp_path).scanners.cdk_nag.model_dump()
        assert cdk_nag["enabled"] is False
        assert cdk_nag["options"]["probe_from_base"] == "kept"

    def test_patch_pointer_matches_the_other_spelling(self, tmp_path):
        _write(
            tmp_path / "base.yaml",
            "project_name: p\nscanners:\n  cdk-nag:\n    enabled: true\n",
        )
        _write(
            tmp_path / ".ash.yaml",
            """
            extends: base.yaml
            patch:
              - {op: replace, path: /scanners/cdk_nag/enabled, value: false}
            """,
        )
        assert _load(tmp_path).scanners.cdk_nag.enabled is False

    def test_one_file_with_both_spellings_keeps_alias_winning(self, tmp_path):
        # A file with no extends is read exactly as before #289, so #691's rule
        # (alias wins key by key) still decides between the two spellings.
        _write(
            tmp_path / ".ash.yaml",
            """
            project_name: p
            scanners:
              cdk_nag:
                enabled: true
              cdk-nag:
                enabled: false
            """,
        )
        assert _load(tmp_path).scanners.cdk_nag.enabled is False


class TestConfigOverrides:
    def test_overrides_apply_after_extends_and_patch(self, tmp_path):
        _write(
            tmp_path / "base.yaml",
            "project_name: from-base\nfail_on_findings: false\n"
            "fail_on_incomplete_scanners: false\n"
            "global_settings:\n  severity_threshold: LOW\n",
        )
        _write(
            tmp_path / ".ash.yaml",
            """
            extends: base.yaml
            patch:
              - {op: replace, path: /global_settings/severity_threshold, value: HIGH}
            """,
        )
        config = resolve_config(
            source_dir=tmp_path,
            config_overrides=[
                "fail_on_findings=true",
                "global_settings.severity_threshold=CRITICAL",
            ],
        )
        assert config.fail_on_findings is True
        assert config.global_settings.severity_threshold == "CRITICAL"
        # Untouched by the overrides, so still the base's.
        assert config.project_name == "from-base"
        assert config.fail_on_incomplete_scanners is False

    def test_override_of_an_aliased_section_keeps_the_base_settings(self, tmp_path):
        _write(
            tmp_path / "base.yaml",
            """
            project_name: p
            scanners:
              cdk-nag:
                enabled: false
                options:
                  probe_from_base: kept
            """,
        )
        _write(tmp_path / ".ash.yaml", "extends: base.yaml\n")
        config = resolve_config(
            source_dir=tmp_path,
            config_overrides=["scanners.cdk-nag.options.probe_from_override=added"],
        )
        cdk_nag = config.scanners.cdk_nag.model_dump()
        assert cdk_nag["enabled"] is False
        assert cdk_nag["options"]["probe_from_base"] == "kept"
        assert cdk_nag["options"]["probe_from_override"] == "added"


class TestEnvInterpolationAcrossTheChain:
    def test_every_file_in_the_chain_uses_the_allowlist(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ASH_TEST_EXTENDS_NAME", "named-by-env")
        monkeypatch.setenv("DEMO_UNLISTED_EXTENDS_VAR", "must-not-appear")
        _write(
            tmp_path / "base.yaml",
            """
            project_name: ${ASH_TEST_EXTENDS_NAME:None}
            global_settings:
              ignore_paths:
                - path: ${DEMO_UNLISTED_EXTENDS_VAR:None}
                  reason: unlisted names stay literal
            """,
        )
        _write(tmp_path / ".ash.yaml", "extends: base.yaml\n")
        config = _load(tmp_path)
        assert config.project_name == "named-by-env"
        assert (
            config.global_settings.ignore_paths[0].path
            == "${DEMO_UNLISTED_EXTENDS_VAR:None}"
        )

    def test_patch_values_use_the_allowlist(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ASH_TEST_PATCH_NAME", "patched-by-env")
        monkeypatch.setenv("DEMO_UNLISTED_PATCH_VAR", "must-not-appear")
        _write(tmp_path / "base.yaml", "project_name: base\n")
        _write(
            tmp_path / ".ash.yaml",
            """
            extends: base.yaml
            patch:
              - op: replace
                path: /project_name
                value: ${ASH_TEST_PATCH_NAME:None}
              - op: add
                path: /external_reports_to_include
                value: ["${DEMO_UNLISTED_PATCH_VAR:None}"]
            """,
        )
        config = _load(tmp_path)
        assert config.project_name == "patched-by-env"
        assert config.external_reports_to_include == ["${DEMO_UNLISTED_PATCH_VAR:None}"]


class TestExtendsAcrossFormats:
    def test_pyproject_tool_ash_extends_a_yaml_base(self, tmp_path):
        _write(
            tmp_path / ".ash" / "org-base.yaml",
            "project_name: org\nfail_on_findings: false\n",
        )
        _write(
            tmp_path / "pyproject.toml",
            """
            [project]
            name = "demo"

            [tool.ash]
            extends = ".ash/org-base.yaml"
            project_name = "from-pyproject"
            """,
        )
        config = _load(tmp_path)
        assert config.project_name == "from-pyproject"
        assert config.fail_on_findings is False

    def test_pyproject_tool_ash_patch(self, tmp_path):
        _write(tmp_path / "base.yaml", "project_name: base\n")
        _write(
            tmp_path / "pyproject.toml",
            """
            [tool.ash]
            extends = ["base.yaml"]
            patch = [{op = "add", path = "/fail_on_findings", value = false}]
            """,
        )
        config = _load(tmp_path)
        assert config.project_name == "base"
        assert config.fail_on_findings is False

    def test_yaml_extends_pyproject_reads_tool_ash(self, tmp_path):
        _write(
            tmp_path / "pyproject.toml",
            '[project]\nname = "x"\n[tool.ash]\nproject_name = "from-table"\n',
        )
        _write(tmp_path / ".ash" / ".ash.yaml", "extends: ../pyproject.toml\n")
        assert _load(tmp_path).project_name == "from-table"

    def test_ashrc_toml_extends_json(self, tmp_path):
        _write(tmp_path / "base.json", '{"project_name": "json-base"}\n')
        _write(
            tmp_path / "ashrc.toml", 'extends = "base.json"\nfail_on_findings = false\n'
        )
        config = _load(tmp_path)
        assert config.project_name == "json-base"
        assert config.fail_on_findings is False

    def test_from_file_resolves_extends_too(self, tmp_path):
        _write(tmp_path / "base.yaml", "project_name: via-from-file\n")
        child = _write(tmp_path / "child.yaml", "extends: base.yaml\n")
        assert AshConfig.from_file(child).project_name == "via-from-file"
