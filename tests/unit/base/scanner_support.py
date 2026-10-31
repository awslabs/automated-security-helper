# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A concrete scanner and the files it works on, for the tests of the scanner base.

These lived in ``test_scanner_plugin_coverage``, and tests of other behaviors
imported them from that test module by their private names, which tied them to
it and to the way the test tree is imported. Test modules import them from here
instead; ``test_scanner_plugin_coverage`` keeps its old names for the modules
that have not moved.
"""

from __future__ import annotations

from pathlib import Path
from typing import ClassVar, Literal

from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.core.enums import OfflineStrategy, ScannerToolType


class StubConfig(ScannerPluginConfigBase):
    name: Literal["stub"] = "stub"


def build_scanner(plugin_context, execute_scan=None, deps_ok=True, **fields):
    """Build a concrete ScannerPluginBase subclass over the real init path."""

    class StubScanner(ScannerPluginBase):
        offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.BUNDLED

        def model_post_init(self, context):
            self.command = "stub-tool"
            self.tool_type = ScannerToolType.SAST
            super().model_post_init(context)

        def validate_plugin_dependencies(self) -> bool:
            return deps_ok

        def _execute_scan(self, target, target_type, global_ignore_paths):
            if execute_scan is None:
                raise NotImplementedError
            return execute_scan(self, target, target_type, global_ignore_paths)

    return StubScanner(config=StubConfig(), context=plugin_context, **fields)


def populated_target(tmp_path, name="target") -> Path:
    """A directory holding one Python file, for a scan that needs something to read."""
    target = tmp_path / name
    target.mkdir()
    (target / "app.py").write_text("x = 1\n")
    return target


def execute_writing(content=None):
    """Return an _execute_scan impl that writes ``content`` to the results file."""

    def _impl(scanner, target, target_type, global_ignore_paths):
        results = scanner.results_dir / "results.json"
        results.parent.mkdir(parents=True, exist_ok=True)
        if content is not None:
            results.write_text(content)
        return ["stub-tool", "--scan"], results, None

    return _impl


MINIMAL_SARIF = {
    "version": "2.1.0",
    "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
    "runs": [
        {
            "tool": {"driver": {"name": "stub-tool", "version": "1.0.0"}},
            "results": [],
        }
    ],
}
