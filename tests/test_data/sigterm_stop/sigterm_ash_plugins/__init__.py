# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A fixture scanner plugin whose tool blocks until something stops it.

Loaded through ``ash_plugin_modules`` like a third-party plugin (the package
name ends in ``_ash_plugins`` because the loader admits only ASH's plugin
namespace), and spawns its
tool (blocker.py, named by ``ASH_SIGTERM_STOP_BLOCKER``) through
``_run_subprocess`` exactly like a builtin scanner, so the SIGTERM test
exercises the real spawn and stop path rather than calling the cancellation
machinery directly. The tool writes its pid to the file
``ASH_SIGTERM_STOP_PID_FILE`` names, ignores SIGTERM, and sleeps far longer
than the test waits: only the stop path's group SIGKILL ends it.
"""

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


class SigtermStopScannerConfigOptions(ScannerOptionsBase):
    pass


class SigtermStopScannerConfig(ScannerPluginConfigBase):
    name: Literal["sigterm-stop"] = "sigterm-stop"
    enabled: bool = True
    options: Annotated[
        SigtermStopScannerConfigOptions, Field(description="none")
    ] = SigtermStopScannerConfigOptions()


@ash_scanner_plugin
class SigtermStopScanner(ScannerPluginBase[SigtermStopScannerConfig]):
    def model_post_init(self, context):
        if self.config is None:
            self.config = SigtermStopScannerConfig()
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
        results_dir = Path(self.results_dir) / target_type
        results_dir.mkdir(parents=True, exist_ok=True)
        self._run_subprocess(
            [
                sys.executable,
                os.environ["ASH_SIGTERM_STOP_BLOCKER"],
                os.environ["ASH_SIGTERM_STOP_PID_FILE"],
            ],
            results_dir=results_dir,
            stdout_preference="write",
            stderr_preference="write",
        )
        self._post_scan(target, target_type)
        return {"findings": []}


ASH_SCANNERS = [SigtermStopScanner]
