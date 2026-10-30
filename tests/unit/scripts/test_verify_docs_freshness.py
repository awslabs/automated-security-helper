# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""scripts/verify_docs_freshness.py: the comparison helpers.

* an inventory row covers a code name only when the whole normalized name
  matches, so a row containing another name as a substring hides nothing;
* a config-discovery list that places an ashrc name or pyproject.toml under
  ``.ash/`` is reported;
* an options block that uses the ``!ENV`` tag is parsed, not skipped;
* a plugin documented under its underscore spelling finds the dashed model;
* a table header is only a header when a real delimiter row follows it;
* a tool registered under ``@mcp.tool(name=...)`` is demanded under that name;
* a pre-release pin is its own tag, not the release it starts with;
* a loose config-discovery list is one inventory;
* the suppression-key check reads YAML and JSON blocks that configure
  suppressions, and nothing else;
* a plugin module that fails to import is named, and one broken at import is
  an error rather than a silent skip;
* a multi-document options block is checked document by document, an alias is
  an accepted option key, and a wrong value is reported with its message.
"""

from __future__ import annotations

import importlib
import textwrap
from pathlib import Path
from typing import Literal

import pytest
from pydantic import AliasChoices, BaseModel, Field, ValidationError

pytestmark = pytest.mark.unit


@pytest.fixture
def freshness(script_loader):
    return script_loader("verify_docs_freshness")


TABLE = """\
| Reporter | Output |
|---|---|
| gitlab-cyclonedx | ash.gl-dependency-scanning-report.cdx.json |
| cfn-nag (CloudFormation) | ash.summary.txt |
"""


class TestCompareInventories:
    def test_a_row_containing_the_name_as_a_substring_does_not_cover_it(
        self, freshness
    ):
        code = {"cyclonedx": "CycloneDXReporter", "gitlab-cyclonedx": "GitLabReporter"}
        failures = freshness.compare_inventories(
            "reporters", code, TABLE, "Reporter", "reporters.md"
        )
        assert any(
            "'cyclonedx'" in f and "is in the code but no row" in f for f in failures
        )

    def test_a_leftover_row_is_not_covered_by_a_longer_name(self, freshness):
        code = {"gitlab-cyclonedx": "GitLabReporter", "cfn-nag": "CfnNagScanner"}
        table = TABLE + "| cyclonedx | ash.cdx.json |\n"
        failures = freshness.compare_inventories(
            "reporters", code, table, "Reporter", "reporters.md"
        )
        assert any(
            "row 'cyclonedx'" in f and "names nothing in the code" in f
            for f in failures
        )

    def test_a_trailing_parenthetical_is_not_part_of_the_name(self, freshness):
        code = {"gitlab-cyclonedx": "GitLabReporter", "cfn_nag": "CfnNagScanner"}
        failures = freshness.compare_inventories(
            "reporters", code, TABLE, "Reporter", "reporters.md"
        )
        assert failures == []


class TestConfigDiscoveryLists:
    SUPPORTED = {".ash.yaml", ".ash.yml", "ash.yaml"}
    NEWER = {".ashrc.yaml", "pyproject.toml"}

    def test_a_newer_name_under_dot_ash_is_reported(self, freshness):
        lines = [
            "1. `.ash/.ash.yaml`",
            "2. `.ash/.ash.yml`",
            "3. `.ash/ash.yaml`",
            "4. `.ash/.ashrc.yaml`",
            "5. `.ash/pyproject.toml`",
        ]
        failures, lists = freshness._config_list_problems(
            "docs/x.md", lines, self.SUPPORTED, self.NEWER
        )
        assert lists == 1
        assert any("under .ash/" in f and ".ashrc.yaml" in f for f in failures)

    def test_a_complete_list_at_the_right_places_is_clean(self, freshness):
        lines = [
            "1. `.ash/.ash.yaml`",
            "2. `.ash/.ash.yml`",
            "3. `.ash/ash.yaml`",
            "4. `.ashrc.yaml`",
            "5. `pyproject.toml`",
        ]
        failures, lists = freshness._config_list_problems(
            "docs/x.md", lines, self.SUPPORTED, self.NEWER
        )
        assert (failures, lists) == ([], 1)

    def test_a_single_example_is_not_an_inventory(self, freshness):
        failures, lists = freshness._config_list_problems(
            "docs/x.md", ["- `.ash/.ash.yaml`", "prose"], self.SUPPORTED, self.NEWER
        )
        assert (failures, lists) == ([], 0)


class TestOptionsYaml:
    def test_an_env_tag_parses_as_its_text(self, freshness):
        parsed = freshness._load_options_yaml(
            "scanners:\n  bandit:\n    options:\n      config_file: !ENV ${BANDIT_CONFIG}\n"
        )
        value = parsed["scanners"]["bandit"]["options"]["config_file"]
        assert value == "${BANDIT_CONFIG}"
        # Marked, so the value check can tell it from a documented literal.
        assert isinstance(value, freshness._EnvReference)
        assert isinstance(value, str)

    def test_invalid_yaml_still_returns_none(self, freshness):
        assert freshness._load_options_yaml("scanners: [unclosed") is None


class _IntOptions(BaseModel):
    depth: int = 1
    config_file: str | None = None


class TestOptionsBlockProblems:
    """Value validation skips !ENV values; the key check still covers them."""

    _KINDS = (("scanners", "ScannerConfig", None),)
    _MODELS = {"scanners": {"demo": _IntOptions}}

    def _problems(self, freshness, options):
        parsed = {"scanners": {"demo": {"options": options}}}
        return freshness._options_block_problems(
            parsed, self._MODELS, self._KINDS, "page.md"
        )

    def test_an_env_value_on_a_non_string_field_is_not_a_failure(self, freshness):
        """At the base the ${VAR} text was validated as the int and failed."""
        options = freshness._load_options_yaml(
            "depth: !ENV ${DEPTH}\nconfig_file: bandit.yaml\n"
        )
        assert self._problems(freshness, options) == []

    def test_a_literal_that_does_not_validate_is_still_reported(self, freshness):
        problems = self._problems(freshness, {"depth": "deep"})
        assert len(problems) == 1
        assert "does not validate against _IntOptions" in problems[0]
        assert "depth" in problems[0]

    def test_an_env_value_under_an_unknown_key_is_still_reported(self, freshness):
        options = freshness._load_options_yaml("bogus: !ENV ${X}\n")
        problems = self._problems(freshness, options)
        assert len(problems) == 1
        assert "options.bogus is not a field of _IntOptions" in problems[0]


class TestModelLookup:
    def test_the_underscore_spelling_finds_the_dashed_model(self, freshness):
        class CdkNagOptions:
            pass

        models = {"cdk-nag": CdkNagOptions}
        assert freshness._model_for(models, "cdk_nag") is CdkNagOptions
        assert freshness._model_for(models, "cdk-nag") is CdkNagOptions

    def test_an_unknown_plugin_finds_nothing(self, freshness):
        assert freshness._model_for({"cdk-nag": object}, "third-party") is None


class TestTableFirstColumn:
    def test_a_data_row_named_like_the_header_is_not_a_header(self, freshness):
        """At the base a blank line passed the delimiter test, so the first table's
        'Reporter' row shadowed the real Reporter table below it."""
        text = (
            "| Name | Role |\n|---|---|\n| Reporter | writes reports |\n\n"
            "| Reporter | Output |\n|---|---|\n| sarif | ash.sarif |\n"
        )
        assert freshness.table_first_column(text, "Reporter") == ["sarif"]

    def test_a_delimiter_row_needs_a_dash_and_a_pipe(self, freshness):
        assert freshness._is_delimiter_row("|---|:--:|")
        assert freshness._is_delimiter_row("--- | ---")
        assert not freshness._is_delimiter_row("")
        assert not freshness._is_delimiter_row("|   |")
        assert not freshness._is_delimiter_row("---")


class TestMcpToolNames:
    def test_a_name_argument_is_the_registered_name(
        self, freshness, monkeypatch, tmp_path
    ):
        """At the base the function's own name was taken."""
        source = textwrap.dedent(
            """
            @mcp.tool(name="list_things")
            async def list_things_impl():
                pass


            @mcp.tool()
            def plain_tool():
                pass


            @mcp.tool
            def bare_decorator():
                pass
            """
        )
        server = tmp_path / "mcp_server.py"
        server.write_text(source, encoding="utf-8")
        monkeypatch.setattr(freshness, "MCP_SERVER_PY", server)
        assert set(freshness.mcp_tool_names()) == {
            "list_things",
            "plain_tool",
            "bare_decorator",
        }


class TestVersionPins:
    def test_a_pre_release_pin_is_its_own_token(self, freshness):
        pins = freshness._version_pins(
            "Install ash@v3.7.0 or ash@v3.7.0-beta. Earlier: @v3.6.1rc1,"
        )
        assert pins == ["@v3.7.0", "@v3.7.0-beta", "@v3.6.1rc1"]

    def test_a_stale_pre_release_pin_does_not_satisfy_the_release(
        self, freshness, monkeypatch, tmp_path
    ):
        """At the base '@v3.0.0-beta.1' read as the current '@v3.0.0'."""
        readme = tmp_path / "README.md"
        readme.write_text("pip install ash@v3.0.0-beta.1\n", encoding="utf-8")
        install = tmp_path / "install.md"
        install.write_text("pip install ash@v3.0.0\n", encoding="utf-8")
        monkeypatch.setattr(freshness, "README_MD", readme)
        monkeypatch.setattr(freshness, "INSTALL_MD", install)
        monkeypatch.setattr(freshness, "get_version_from_pyproject", lambda: "3.0.0")
        failures = freshness.check_version_consistency()
        assert len(failures) == 1
        assert "README.md" in failures[0]
        assert "@v3.0.0-beta.1" in failures[0]

    def test_a_floating_major_tag_of_the_current_version_is_not_outdated(
        self, freshness, monkeypatch, tmp_path
    ):
        """The install pages document the moving `@v3` tag beside the exact pin;
        the whole-token comparison must not report it as a stale release."""
        readme = tmp_path / "README.md"
        readme.write_text(
            "Pin `@v3.7.1` for a reproducible install. The floating `@v3` tag "
            "follows the latest 3.x release; `@v3.7` follows the 3.7 line.\n",
            encoding="utf-8",
        )
        install = tmp_path / "install.md"
        install.write_text("pip install ash@v3.7.1\n", encoding="utf-8")
        monkeypatch.setattr(freshness, "README_MD", readme)
        monkeypatch.setattr(freshness, "INSTALL_MD", install)
        monkeypatch.setattr(freshness, "get_version_from_pyproject", lambda: "3.7.1")
        assert freshness.check_version_consistency() == []

    def test_a_tag_of_another_line_is_outdated(self, freshness, monkeypatch, tmp_path):
        readme = tmp_path / "README.md"
        readme.write_text("pip install ash@v3.7.1 or ash@v3.6\n", encoding="utf-8")
        install = tmp_path / "install.md"
        install.write_text("pip install ash@v3.7.1\n", encoding="utf-8")
        monkeypatch.setattr(freshness, "README_MD", readme)
        monkeypatch.setattr(freshness, "INSTALL_MD", install)
        monkeypatch.setattr(freshness, "get_version_from_pyproject", lambda: "3.7.1")
        failures = freshness.check_version_consistency()
        assert len(failures) == 1
        assert "@v3.6" in failures[0]

    def test_floating_tag_shapes(self, freshness):
        assert freshness._is_floating_tag("@v3", "3.7.1")
        assert freshness._is_floating_tag("@v3.7", "3.7.1")
        assert not freshness._is_floating_tag("@v3.7.1", "3.7.1")
        assert not freshness._is_floating_tag("@v3.6", "3.7.1")
        assert not freshness._is_floating_tag("@v3.7.1-beta.1", "3.7.1")
        assert not freshness._is_floating_tag("@v3-beta", "3.7.1")
        assert not freshness._is_floating_tag("@v4", "3.7.1")


class TestLooseConfigDiscoveryLists:
    SUPPORTED = {".ash.yaml", ".ash.yml", "ash.yaml"}
    NEWER = {".ashrc.yaml", "pyproject.toml"}

    def test_a_blank_line_between_items_keeps_one_inventory(self, freshness):
        """At the base the blank lines closed the run, so the loose list was three
        single examples and none of them was checked."""
        lines = [
            "1. `.ash/.ash.yaml`",
            "",
            "2. `.ash/.ash.yml`",
            "",
            "3. `.ash/ash.yaml`",
            "",
            "Prose after the list.",
        ]
        failures, lists = freshness._config_list_problems(
            "docs/x.md", lines, self.SUPPORTED, self.NEWER
        )
        assert (failures, lists) == ([], 1)

    def test_a_loose_list_missing_a_name_is_reported(self, freshness):
        lines = ["1. `.ash/.ash.yaml`", "", "2. `.ash/.ash.yml`"]
        failures, lists = freshness._config_list_problems(
            "docs/x.md", lines, self.SUPPORTED, self.NEWER
        )
        assert lists == 1
        assert any("omits ['ash.yaml']" in f for f in failures)


class TestSuppressionFieldName:
    @pytest.fixture
    def page(self, freshness, monkeypatch, tmp_path):
        """Write one docs page under a temporary root and point the check at it."""

        def _page(text: str) -> list[str]:
            md = tmp_path / "docs" / "page.md"
            md.parent.mkdir(parents=True, exist_ok=True)
            md.write_text(textwrap.dedent(text), encoding="utf-8")
            monkeypatch.setattr(freshness, "REPO_ROOT", tmp_path)
            monkeypatch.setattr(freshness, "collect_md_files", lambda: [md])
            return freshness.check_suppression_field_name()

        return _page

    def test_a_yaml_suppression_with_file_path_is_reported(self, page):
        failures = page(
            """
            ```yaml
            global_settings:
              suppressions:
                - rule_id: B101
                  file_path: src/x.py
            ```
            """
        )
        assert len(failures) == 1
        assert "docs/page.md" in failures[0] and "file_path:" in failures[0]

    def test_a_json_suppression_with_file_path_is_reported(self, page):
        """At the base the block-style key regex never matched a quoted key."""
        failures = page(
            """
            ```json
            {"global_settings": {"suppressions": [
              {"rule_id": "B101", "file_path": "src/x.py"}
            ]}}
            ```
            """
        )
        assert len(failures) == 1

    def test_a_flow_mapping_suppression_is_reported(self, page):
        failures = page(
            """
            ```yaml
            suppressions:
              - {rule_id: B101, file_path: src/x.py}
            ```
            """
        )
        assert len(failures) == 1

    def test_a_python_annotation_near_rule_id_is_not_reported(self, page):
        """At the base `file_path: str` within twenty lines of `rule_id` was reported."""
        failures = page(
            """
            ```python
            class Finding(BaseModel):
                rule_id: str
                file_path: str
            ```
            """
        )
        assert failures == []

    def test_a_flat_finding_example_is_not_reported(self, page):
        """At the base ASH's own output fields (file_path, rule_id, is_suppressed)
        read as a wrong suppression key."""
        failures = page(
            """
            ```yaml
            findings:
              - rule_id: B101
                file_path: src/x.py
                is_suppressed: false
            ```
            """
        )
        assert failures == []

    def test_a_correct_suppression_is_not_reported(self, page):
        failures = page(
            """
            ```yaml
            suppressions:
              - rule_id: B101
                path: src/x.py
            ```
            """
        )
        assert failures == []


def _write_package(root: Path, name: str, modules: dict[str, str]) -> None:
    package = root / name
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    for module_name, source in modules.items():
        (package / f"{module_name}.py").write_text(
            textwrap.dedent(source), encoding="utf-8"
        )


GOOD_PLUGIN = """
from pydantic import BaseModel


class OptionsBase(BaseModel):
    pass


class DemoScannerConfigOptions(OptionsBase):
    depth: int = 1


class DemoScannerConfig(BaseModel):
    name: str = "demo"
"""


class TestPluginOptionModels:
    def test_an_import_error_is_skipped_and_named(
        self, freshness, monkeypatch, tmp_path
    ):
        """At the base the skip was silent."""
        monkeypatch.syspath_prepend(str(tmp_path))
        _write_package(
            tmp_path,
            "fakeplugs_skip",
            {
                "good": GOOD_PLUGIN,
                "missing_dep": 'raise ImportError("no module named some_extra")\n',
            },
        )
        package = importlib.import_module("fakeplugs_skip")
        base = importlib.import_module("fakeplugs_skip.good").OptionsBase
        notes: list[str] = []
        models = freshness._plugin_option_models(
            "ScannerConfig", base, package=package, notes=notes
        )
        assert list(models) == ["demo"]
        assert len(notes) == 1
        assert "fakeplugs_skip.missing_dep" in notes[0]
        assert "some_extra" in notes[0]

    def test_a_plugin_broken_at_import_is_an_error(
        self, freshness, monkeypatch, tmp_path
    ):
        """At the base any exception was swallowed and the gate passed."""
        monkeypatch.syspath_prepend(str(tmp_path))
        _write_package(
            tmp_path,
            "fakeplugs_broken",
            {"good": GOOD_PLUGIN, "broken": 'raise RuntimeError("bad plugin")\n'},
        )
        package = importlib.import_module("fakeplugs_broken")
        base = importlib.import_module("fakeplugs_broken.good").OptionsBase
        with pytest.raises(RuntimeError, match="bad plugin"):
            freshness._plugin_option_models("ScannerConfig", base, package=package)


class TestOptionsDocuments:
    def test_every_document_of_a_block_is_read(self, freshness):
        """At the base a two-document block raised and was skipped whole."""
        docs = freshness._load_options_documents("a: 1\n---\nb: 2\n")
        assert docs == [{"a": 1}, {"b": 2}]

    def test_invalid_yaml_yields_no_document(self, freshness):
        assert freshness._load_options_documents("scanners: [unclosed") == []

    def test_an_env_tag_parses_in_every_document(self, freshness):
        docs = freshness._load_options_documents("a: !ENV ${X}\n---\nb: 2\n")
        assert docs[0] == {"a": "${X}"}


class _Aliased(BaseModel):
    severity_threshold: Literal["LOW", "HIGH"] = Field(
        "LOW", alias="severity-threshold"
    )
    config_file: str = Field(
        "", validation_alias=AliasChoices("config_file", "config", "cfg")
    )


class TestAcceptedOptionKeys:
    def test_aliases_are_accepted_keys(self, freshness):
        """At the base only the field names were accepted."""
        assert freshness._accepted_option_keys(_Aliased) == {
            "severity_threshold",
            "severity-threshold",
            "config_file",
            "config",
            "cfg",
        }

    def test_a_plain_model_accepts_its_field_names(self, freshness):
        class Plain(BaseModel):
            depth: int = 1

        assert freshness._accepted_option_keys(Plain) == {"depth"}


class TestValidationDetail:
    def test_a_wrong_value_is_reported_with_its_message(self, freshness):
        """At the base the detail was the field name alone."""
        try:
            _Aliased.model_validate({"severity-threshold": "low"})
        except ValidationError as exc:
            detail = freshness._validation_detail(exc)
        else:  # pragma: no cover - the value is wrong by construction
            pytest.fail("the value validated")
        assert detail.startswith("severity-threshold: Input should be")
