# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A config file inside the scanned tree naming a module outside the namespace refuses too.

``config/plugin_module_trust.py`` limits what a config file inside the scanned tree
may add to ``ash_plugin_modules``: only modules installed outside the tree. It runs
before the scan's namespace refusal and keeps every name outside the plugin
namespace, unimported, so the scan refuses it with exit code 3 whether the name
cannot be imported, resolves inside the tree, or is installed outside it.

These run ASH the way ``test_refused_plugin_modules.py`` does, with its harness: a
fresh interpreter, a marker file written by the package's ``__init__``, and every
tool directory under the test's temporary directory.
"""

from __future__ import annotations

import os
import sys

from automated_security_helper.config.resolve_config import resolve_config
from tests.unit.plugins.test_refused_plugin_modules import (
    REFUSED,
    _assert_refused,
    _Run,
)

IN_TREE = "zz_intree_pkg"
NOT_IMPORTABLE = "another_plugin_module"


def _in_tree_config(run: _Run, name: str) -> None:
    (run.tree / ".ash").mkdir(exist_ok=True)
    (run.tree / ".ash" / ".ash.yaml").write_text(
        f"project_name: tree\nash_plugin_modules:\n  - {name}\n", encoding="utf-8"
    )


class TestAnInTreeConfigNamingAModuleOutsideTheNamespace:
    def test_a_name_that_cannot_be_imported(self, tmp_path):
        run = _Run(tmp_path)
        _in_tree_config(run, NOT_IMPORTABLE)

        completed = run.run("cli", {"args": run.scan_args()})

        assert NOT_IMPORTABLE in completed.stdout + completed.stderr
        assert completed.returncode == 3, completed.stdout[-2500:]

    def test_a_package_inside_the_scanned_tree(self, tmp_path):
        run = _Run(tmp_path)
        package = run.tree / IN_TREE
        package.mkdir()
        (package / "__init__.py").write_text(
            "import os, pathlib\n"
            "_marker = os.environ.get('PLUGIN_IMPORT_MARKER')\n"
            "if _marker:\n"
            "    pathlib.Path(_marker, __name__).write_text('imported')\n",
            encoding="utf-8",
        )
        _in_tree_config(run, IN_TREE)
        python_path = os.pathsep.join([str(run.site), str(run.tree)])

        completed = run.run(
            "cli", {"args": run.scan_args()}, {"PYTHONPATH": python_path}
        )

        assert IN_TREE not in run.imported(), completed.stdout[-2500:]
        assert completed.returncode == 3, completed.stdout[-2500:]

    def test_an_installed_package_outside_the_tree(self, tmp_path):
        """Control: the case that already refused, through the same harness."""
        run = _Run(tmp_path)
        _in_tree_config(run, REFUSED)

        _assert_refused(run, run.run("cli", {"args": run.scan_args()}))


class TestTheTrustFilterLeavesTheNameToTheRefusal:
    def test_the_resolved_config_keeps_a_name_outside_the_namespace(
        self, tmp_path, monkeypatch
    ):
        """In process: resolution keeps the name, unimported, for the scan to refuse."""
        source = tmp_path / "repo"
        (source / IN_TREE).mkdir(parents=True)
        (source / IN_TREE / "__init__.py").write_text("LOADED = True\n")
        (source / ".ash").mkdir()
        (source / ".ash" / ".ash.yaml").write_text(
            f"project_name: repo\nash_plugin_modules:\n  - {IN_TREE}\n"
            f"  - {NOT_IMPORTABLE}\n"
        )
        monkeypatch.syspath_prepend(str(source))
        monkeypatch.chdir(source)

        config = resolve_config(source_dir=source)

        assert config.ash_plugin_modules == [IN_TREE, NOT_IMPORTABLE]
        assert IN_TREE not in sys.modules
