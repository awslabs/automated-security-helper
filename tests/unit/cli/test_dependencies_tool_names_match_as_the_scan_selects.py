# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A ``--tool`` name is matched as the scan selects scanners: lower-cased, stripped.

The scan selects its scanners by ``name.lower().strip()``
(core.phases.scan_phase), so ``bandit`` and ``Bandit`` name the same scanner to
it. The installer used to compare the typed name exactly, so ``--tool Bandit``
read as a tool this ASH lacks: refused with exit 2, or with
``ASH_DEPENDENCIES_UNKNOWN_TOOLS=skip`` skipped with exit 0, installing nothing
for a scanner the scan would then run. A differently-cased or blank-padded name
now selects the plugin it names, under the plugin's own spelling; a name no plugin
has is still refused in the spelling the caller typed.
"""

import io

import pytest
import typer
from rich.console import Console
from typer.testing import CliRunner

from automated_security_helper.cli import dependencies as dependencies_module
from automated_security_helper.cli.dependencies import (
    EXIT_BAD_SELECTION,
    EXIT_OK,
    dependencies_app,
)

pytestmark = pytest.mark.unit

runner = CliRunner()
SETTING = "ASH_DEPENDENCIES_UNKNOWN_TOOLS"


class TestWithTheRealRegistry:
    @pytest.fixture(autouse=True)
    def _isolate(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv(SETTING, raising=False)
        monkeypatch.setenv("ASH_BIN_PATH", str(tmp_path / "bin"))
        self.bin_args = ["--bin-path", str(tmp_path / "bin")]
        self.panels = io.StringIO()
        monkeypatch.setattr(
            dependencies_module,
            "console",
            Console(file=self.panels, width=200, no_color=True),
        )
        self.selected = []
        real = dependencies_module._report_and_exit

        def recording(outcomes, requested_tools):
            self.selected.append(([o.name for o in outcomes], list(requested_tools)))
            return real(outcomes, requested_tools=requested_tools)

        monkeypatch.setattr(dependencies_module, "_report_and_exit", recording)

    def _invoke(self, *args):
        return runner.invoke(dependencies_app, [*args, *self.bin_args])

    def _output(self, result) -> str:
        return self.panels.getvalue() + result.output

    @pytest.mark.parametrize("typed", ["Archive", "ARCHIVE", " archive "])
    def test_a_name_in_another_spelling_selects_the_plugin(self, typed):
        result = self._invoke("--tool", typed)
        output = self._output(result)
        assert result.exit_code == EXIT_OK, output
        assert self.selected == [(["archive"], ["archive"])], self.selected
        assert "Unknown tool" not in output, output

    def test_with_skip_set_the_plugin_is_installed_not_skipped(self, monkeypatch):
        """The failure this pins: the name was skipped as unknown, with exit 0."""
        monkeypatch.setenv(SETTING, "skip")
        result = self._invoke("--tool", "Archive")
        output = self._output(result)
        assert result.exit_code == EXIT_OK, output
        assert self.selected == [(["archive"], ["archive"])], self.selected
        assert "not known" not in output.lower(), output
        assert "Nothing to install" not in output, output

    def test_a_name_of_an_unselected_type_is_still_named_as_typed(self):
        result = self._invoke("--plugin-type", "converter", "--tool", "Bandit")
        output = self._output(result)
        assert result.exit_code == EXIT_BAD_SELECTION, output
        assert "Bandit is a scanner plugin" in output, output

    def test_a_name_no_plugin_has_is_refused_as_typed(self):
        result = self._invoke("--tool", "Not-A-Real-Tool")
        output = self._output(result)
        assert result.exit_code == EXIT_BAD_SELECTION, output
        assert "Unknown tool(s): Not-A-Real-Tool" in output, output
        assert self.selected == []

    @pytest.mark.parametrize("typed", ["archiveconverter", " ArchiveConverter"])
    def test_a_deprecated_alias_matches_by_the_same_key(self, typed):
        """`ArchiveConverter` is the alias; its other spellings resolve too."""
        result = self._invoke("--tool", typed)
        output = self._output(result)
        assert result.exit_code == EXIT_OK, output
        assert self.selected == [(["archive"], ["archive"])], self.selected
        assert "Unknown tool" not in output, output


def test_the_selection_key_is_the_scans():
    assert dependencies_module._selection_key(" Bandit ") == "bandit"
    assert dependencies_module._selection_key("cfn-nag") == "cfn-nag"


def test_two_spellings_of_one_alias_warn_once(monkeypatch):
    """Aliases match by key, so `ArchiveConverter` and `archiveconverter` are one
    alias; the repeat check read the typed spelling and warned for each."""
    warnings = io.StringIO()
    monkeypatch.setattr(
        dependencies_module,
        "err_console",
        Console(file=warnings, width=200, no_color=True),
    )

    resolution = dependencies_module._resolve_tool_aliases(
        ["ArchiveConverter", "archiveconverter", " ArchiveConverter "]
    )

    assert resolution == {
        "ArchiveConverter": "archive",
        "archiveconverter": "archive",
        " ArchiveConverter ": "archive",
    }
    assert warnings.getvalue().count("Deprecated:") == 1, warnings.getvalue()


def test_the_alias_table_is_read_when_a_name_is_resolved(monkeypatch):
    """The table, not a copy of it taken at import, resolves an alias: emptied, the
    old name resolves to itself and the caller refuses it as unknown."""
    monkeypatch.setattr(dependencies_module, "DEPRECATED_TOOL_ALIASES", {})

    resolution = dependencies_module._resolve_tool_aliases(["archiveconverter"])

    assert resolution == {"archiveconverter": "archiveconverter"}


class TestCanonicalToolName:
    """Two plugins whose names differ only in case: the exact spelling wins."""

    AVAILABLE = ["Semgrep", "bandit", "semgrep"]

    def test_an_exact_spelling_selects_itself(self):
        assert (
            dependencies_module._canonical_tool_name("Semgrep", self.AVAILABLE)
            == "Semgrep"
        )
        assert (
            dependencies_module._canonical_tool_name("semgrep", self.AVAILABLE)
            == "semgrep"
        )

    def test_another_spelling_falls_back_to_the_key(self):
        assert (
            dependencies_module._canonical_tool_name("Bandit", self.AVAILABLE)
            == "bandit"
        )
        assert (
            dependencies_module._canonical_tool_name(" bandit ", self.AVAILABLE)
            == "bandit"
        )

    def test_an_unknown_name_is_kept_as_typed(self):
        assert (
            dependencies_module._canonical_tool_name("Not-A-Tool", self.AVAILABLE)
            == "Not-A-Tool"
        )

    def test_a_third_spelling_of_two_case_twins_is_ambiguous(self):
        """`SEMGREP` names Semgrep and semgrep alike. The first by registry order
        was picked, silently, and which one that was changed with the ordering."""
        with pytest.raises(dependencies_module.AmbiguousToolName) as raised:
            dependencies_module._canonical_tool_name("SEMGREP", self.AVAILABLE)

        assert raised.value.name == "SEMGREP"
        assert raised.value.matches == ["Semgrep", "semgrep"]

    def test_one_name_two_plugins_declare_is_matched_once(self):
        """Two plugin classes can declare one name, and the declared names reach
        this as a list, so `semgrep` appeared twice, matched itself twice and
        `--tool Semgrep` was refused as ambiguous with itself."""
        assert (
            dependencies_module._canonical_tool_name(
                "Semgrep", ["semgrep", "bandit", "semgrep"]
            )
            == "semgrep"
        )


class TestAmbiguousNamesAreRefused:
    """The scan runs the first of two scanners whose names differ only in case
    and refuses the second as a name already carried (scan_phase,
    _record_duplicate_scanner_name); the installer refuses to pick for the caller
    and names both."""

    AVAILABLE = ["Semgrep", "bandit", "semgrep"]

    @pytest.fixture
    def panels(self, monkeypatch):
        captured = io.StringIO()
        monkeypatch.setattr(
            dependencies_module,
            "console",
            Console(file=captured, width=200, no_color=True),
        )
        return captured

    def test_the_resolution_exits_2_naming_both_plugins(self, panels):
        with pytest.raises(typer.Exit) as raised:
            dependencies_module._canonical_tool_names(
                {"SEMGREP": "SEMGREP"}, self.AVAILABLE
            )

        assert raised.value.exit_code == EXIT_BAD_SELECTION
        output = panels.getvalue()
        assert "Ambiguous tool: SEMGREP" in output, output
        assert "Semgrep, semgrep" in output, output
        assert "exact spelling" in output, output

    def test_an_exact_spelling_beside_the_twins_is_not_ambiguous(self, panels):
        resolution = dependencies_module._canonical_tool_names(
            {"semgrep": "semgrep", "Bandit": "Bandit"}, self.AVAILABLE
        )

        assert resolution == {"semgrep": "semgrep", "Bandit": "bandit"}
        assert panels.getvalue() == ""


class TestRequestedClassesFollowTheResolvedNames:
    """The option check covers the plugins this run builds. Matched by selection
    key, `--tool semgrep` put the Semgrep class back in, and a bad option in the
    Semgrep section exited 3 for a plugin this run never builds."""

    class Semgrep:
        pass

    class semgrep:
        pass

    class unnamed:
        pass

    CANDIDATES = [
        ("scanner", "scanner", Semgrep, "Semgrep"),
        ("scanner", "scanner", semgrep, "semgrep"),
        ("scanner", "scanner", unnamed, None),
    ]

    def test_only_the_exactly_named_plugin_is_checked(self):
        assert dependencies_module._requested_classes(self.CANDIDATES, ["semgrep"]) == {
            self.semgrep,
            self.unnamed,
        }

    def test_a_plugin_known_only_by_building_is_always_checked(self):
        assert dependencies_module._requested_classes(self.CANDIDATES, []) == {
            self.unnamed
        }
