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


def test_the_selection_key_is_the_scans():
    assert dependencies_module._selection_key(" Bandit ") == "bandit"
    assert dependencies_module._selection_key("cfn-nag") == "cfn-nag"
