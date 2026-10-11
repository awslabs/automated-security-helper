# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A fixture scanner plugin whose tool is the malicious escape_probe.py.

Loaded through ``ash_plugin_modules`` exactly like a third-party plugin, and spawns
its tool through ``_run_subprocess`` exactly like a builtin scanner, so the escape test
exercises the real spawn path rather than calling the sandbox directly. The attack
spec is read from the file ASH_SANDBOX_ESCAPE_SPEC names, set by the test.
"""

import json
import os
import sys
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import Field

from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.plugins.decorators import ash_scanner_plugin


class SandboxEscapeScannerConfigOptions(ScannerOptionsBase):
    pass


class SandboxEscapeScannerConfig(ScannerPluginConfigBase):
    name: Literal["sandbox-escape"] = "sandbox-escape"
    enabled: bool = True
    options: Annotated[
        SandboxEscapeScannerConfigOptions, Field(description="none")
    ] = SandboxEscapeScannerConfigOptions()


@ash_scanner_plugin
class SandboxEscapeScanner(ScannerPluginBase[SandboxEscapeScannerConfig]):
    def model_post_init(self, context):
        if self.config is None:
            self.config = SandboxEscapeScannerConfig()
        return super().model_post_init(context)

    def validate_plugin_dependencies(self) -> bool:
        return True

    def _execute_scan(self, target, target_type, global_ignore_paths):  # type: ignore[override]
        raise NotImplementedError("scan() is overridden")

    def scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        config: Any = None,
        *args,
        **kwargs,
    ) -> dict:
        self._pre_scan(target, target_type, config)
        spec = json.loads(Path(os.environ["ASH_SANDBOX_ESCAPE_SPEC"]).read_text())
        results_dir = Path(self.results_dir) / target_type
        results_dir.mkdir(parents=True, exist_ok=True)
        spec["outcome"] = str(results_dir / "outcome.json")
        self._run_subprocess(
            [sys.executable, spec["probe"], json.dumps(spec)],
            results_dir=results_dir,
            stdout_preference="write",
            stderr_preference="write",
        )
        self._post_scan(target, target_type)
        return {"findings": []}


ASH_SCANNERS = [SandboxEscapeScanner]
