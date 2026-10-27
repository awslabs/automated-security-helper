# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``_inject_invocation`` resolves a construction-deferred version probe.

A scanner constructed while the scan phase defers version probes
(``uv_tool_mixin.deferred_tool_version_probes``) carries its probe until
something asks. ``ScannerPluginBase._inject_invocation`` is one asker: the
scanner details it attaches carry ``scanner_version``, so it runs the deferred
probe first, through the mixin's own ``resolve_deferred_tool_version``. This
cell pins that call by its public spelling: the mixin defines no private
``_resolve_deferred_tool_version``, so a call under that name raises
``AttributeError`` here instead of resolving the version.

No tool starts: the uv runner's version read is replaced, and only
``_inject_invocation`` itself runs.
"""

from pathlib import Path

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.uv_tool_mixin import deferred_tool_version_probes
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.plugin_modules.ash_builtin.scanners.semgrep_scanner import (
    SemgrepScanner,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.uv_tool_runner import UVToolRunner

PluginContext.model_rebuild()
AshConfig.model_rebuild()

EMPTY_SARIF = {
    "version": "2.1.0",
    "runs": [
        {
            "tool": {"driver": {"name": "semgrep", "version": "1.0.0", "rules": []}},
            "results": [],
        }
    ],
}


def test_inject_invocation_resolves_the_deferred_version(tmp_path, monkeypatch):
    asked = []

    def version(runner, tool_name, package_name=None, *args, **kwargs):
        asked.append(tool_name)
        return "9.9.9"

    monkeypatch.setattr(UVToolRunner, "get_tool_version", version)

    source = tmp_path / "src"
    source.mkdir()
    output = tmp_path / "out"
    output.mkdir()
    context = PluginContext(source_dir=source, output_dir=output, config=AshConfig())
    with deferred_tool_version_probes():
        scanner = SemgrepScanner(context=context)
    assert scanner.tool_version is None, "construction must defer, not probe"
    assert asked == [], "construction under the deferral asks uv nothing"

    sarif = SarifReport.model_validate(EMPTY_SARIF)
    scanner._inject_invocation(sarif, ["semgrep", "scan"], Path(source))

    assert asked == ["semgrep"], "the injection runs the deferred probe once"
    assert scanner.tool_version == "9.9.9"
    assert sarif.runs[0].invocations, "the invocation record is still written"
