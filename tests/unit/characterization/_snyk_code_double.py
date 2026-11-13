# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The double for ``snyk code test``, with the source, the credentials and the config the
cells scan with.

It lives here, and not in ``test_snyk_code``, so that the cells of other test files can
build the same world without importing a test file. It imports nothing from one.
"""

from __future__ import annotations

from typing import Optional

from automated_security_helper.plugin_modules.ash_snyk_plugins.snyk_code_scanner import (
    SnykCodeScannerConfig,
    SnykCodeScannerConfigOptions,
)
from tests.unit.characterization._harness import (
    ArgvGrammar,
    Exit,
    Outcome,
    ToolCall,
    ToolDouble,
)

SOURCE = {"app.py": 'API_TOKEN = "not-a-secret"\n'}

#: Fake credentials. None of them is a real token or organization.
FAKE_TOKEN = "00000000-0000-4000-8000-00000000c4c4"
FAKE_ORG = "characterization-org"


class SnykDouble(ToolDouble):
    """``snyk code test`` as far as ASH uses it.

    Writes the SARIF fixture to ``--sarif-file-output=``. Exits 1 by default, as
    snyk does when it reports an issue and the fixture holds one; 0 means no issues,
    2 a failure and 3 nothing it supports.
    """

    GRAMMAR = ArgvGrammar(
        value_flags=frozenset({"--severity-threshold"}),
        glued_flags=frozenset({"--sarif-file-output"}),
        min_positionals=3,
        max_positionals=3,
    )
    THRESHOLDS = frozenset({"low", "medium", "high", "critical"})

    def __init__(
        self,
        scan: Optional[Outcome] = None,
        *,
        sarif: Optional[str] = "results.sarif",
    ) -> None:
        self.scan = scan
        self.sarif = sarif

    def run(self, call: ToolCall) -> Outcome:
        parsed = self.GRAMMAR.parse(call)
        if parsed.positionals[:2] != ["code", "test"]:
            raise call.reject("not snyk code test")
        if not call.confined(parsed.positionals[2]).is_dir():
            raise call.reject(f"target {parsed.positionals[2]} is not a directory")
        for value in parsed.flags.get("--severity-threshold", []):
            if value not in self.THRESHOLDS:
                raise call.reject(f"--severity-threshold {value}")
        if self.sarif is not None:
            output = parsed.last("--sarif-file-output")
            if output is None or not call.confined(output).parent.is_dir():
                raise call.reject(f"no usable --sarif-file-output {output}")
            call.write_fixture(f"snyk/{self.sarif}", output)
        if self.scan is not None:
            return self.scan
        return Exit(1, stdout="Testing <target> ...\n\n Open issues: 1\n")


def _config(**options) -> SnykCodeScannerConfig:
    return SnykCodeScannerConfig(options=SnykCodeScannerConfigOptions(**options))


def _with_token(char) -> None:
    char.set_env(SNYK_TOKEN=FAKE_TOKEN, SNYK_CFG_ORG=FAKE_ORG)
