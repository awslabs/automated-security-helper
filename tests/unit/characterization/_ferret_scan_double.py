# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The double for ferret-scan's CLI, with the source and the config the cells scan with.

It lives here, and not in ``test_ferret_scan``, so that the cells of other test files
can build the same world without importing a test file. It imports nothing from one.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from automated_security_helper.plugin_modules.ash_ferret_plugins.ferret_scanner import (
    DEFAULT_FERRET_CONFIG,
    FerretScannerConfig,
    FerretScannerConfigOptions,
)
from tests.unit.characterization._harness import (
    FIXTURES_DIR,
    ArgvGrammar,
    Exit,
    Outcome,
    ToolCall,
    ToolDouble,
)

SOURCE = {"notes.txt": "contact: jane.doe@example.com\n"}


class FerretDouble(ToolDouble):
    """ferret-scan's CLI, as far as ASH uses it.

    ``--version`` prints ``version``. A scan needs ``--format sarif``, an existing
    ``--file`` and ``--config``, and writes the SARIF fixture to ``--output`` in
    ferret-scan 2.5's shape: URIs relative to ``%SRCROOT%``, which names the target.
    Exits 0, as ferret-scan does whether or not it finds anything.
    """

    GRAMMAR = ArgvGrammar(
        value_flags=frozenset(
            {
                "--format",
                "--output",
                "--config",
                "--confidence",
                "--checks",
                "--profile",
                "--exclude",
                "--limit",
                "--disable-ip-types",
                "--validator-budget",
                "--max-live-bytes",
                "--file",
            }
        ),
        bool_flags=frozenset(
            {
                "--recursive",
                "--show-match",
                "--enable-preprocessors",
                "--fail-on-incomplete",
                "--respect-gitignore",
                "--explain",
                "--debug",
                "--verbose",
                "--no-color",
                "--quiet",
            }
        ),
        max_positionals=0,
    )

    def __init__(
        self,
        scan: Optional[Outcome] = None,
        *,
        version: Outcome = Exit(0, stdout="ferret-scan version 2.5.3\n"),
        writes_output: bool = True,
    ) -> None:
        self.scan = scan
        self.version = version
        self.writes_output = writes_output

    def run(self, call: ToolCall) -> Outcome:
        if call.args == ["--version"]:
            return self.version
        parsed = self.GRAMMAR.parse(call)
        if parsed.flags.get("--format") != ["sarif"]:
            raise call.reject("ASH always asks for exactly one --format sarif")
        target = parsed.last("--file")
        if target is None or not call.confined(target).exists():
            raise call.reject(f"--file {target} does not exist")
        config = parsed.last("--config")
        if config is not None and not _config_file(call, config).is_file():
            raise call.reject(f"--config {config} is not a file")
        if self.writes_output:
            output = parsed.last("--output")
            if output is None or not call.confined(output).parent.is_dir():
                raise call.reject(f"no usable --output {output}")
            template = (FIXTURES_DIR / "ferret" / "results.sarif.template").read_text(
                encoding="utf-8"
            )
            call.write(
                output,
                template.replace("@TARGET_URI@", Path(target).as_uri()).encode("utf-8"),
            )
        return self.scan if self.scan is not None else Exit(0)


def _config_file(call: ToolCall, value: str) -> Path:
    """The ``--config`` path, which may be the config bundled in the package.

    That one is in the checkout, not on the host, so it is the one path outside the
    test's tree a double may look at. Every other path goes through ``confined``.
    """
    if os.path.realpath(value) == os.path.realpath(DEFAULT_FERRET_CONFIG):
        return DEFAULT_FERRET_CONFIG
    return call.confined(value)


def _config(**options) -> FerretScannerConfig:
    return FerretScannerConfig(options=FerretScannerConfigOptions(**options))
