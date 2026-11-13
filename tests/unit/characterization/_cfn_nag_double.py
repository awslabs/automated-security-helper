# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``cfn_nag_scan`` as ASH runs it, and the scan of it, for every cell that answers a
cfn-nag launch.

Why this module exists
----------------------
The double lived in the cfn-nag characterization cells, and a cell file elsewhere that
needed a cfn-nag scan imported it from that test module, so changing a test file could
change what another file's cells checked. It lives here, beside the harness it builds
on, and both import it.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Mapping, Optional

from automated_security_helper.plugin_modules.ash_builtin.scanners.cfn_nag_scanner import (
    CfnNagScanner,
    CfnNagScannerConfig,
    CfnNagScannerConfigOptions,
)
from tests.unit.characterization._harness import (
    FIXTURES_DIR,
    ArgvGrammar,
    Exit,
    Outcome,
    ToolCall,
    ToolDouble,
)

#: The cfn-nag fixtures: the findings a scan reports, and the rest.
FIXTURES = FIXTURES_DIR / "cfn-nag"

#: A CloudFormation template with one bucket.
TEMPLATE = (
    "AWSTemplateFormatVersion: '2010-09-09'\n"
    "Resources:\n"
    "  Bucket:\n"
    "    Type: AWS::S3::Bucket\n"
)


def fixture(name: str) -> str:
    """The text of the cfn-nag fixture ``name``."""
    return (FIXTURES / name).read_text(encoding="utf-8")


class CfnNagDouble(ToolDouble):
    """``cfn_nag_scan`` as ASH runs it.

    Prints the findings fixture with its artifact URI set to the one cfn_nag gives
    ``--input-path``: relative to the working directory's real path. Exits with the
    failing-violation count, as cfn_nag does. One trailing positional is accepted
    and ignored, as cfn_nag's option parser leaves it unread.

    The grammar is the subset of cfn_nag_scan's options that ASH passes, not all of
    them. ``--verbose`` is not one of cfn_nag_scan's options at all (0.8.10 has
    ``--debug``): its option parser prints an error and exits 255 before reading
    anything, and so does this double.
    """

    GRAMMAR = ArgvGrammar(
        value_flags=frozenset({"--output-format", "--rule-directory", "--input-path"}),
        bool_flags=frozenset(
            {"--print-suppression", "--isolate-custom-rule-exceptions"}
        ),
        max_positionals=1,
    )

    #: What cfn_nag_scan 0.8.10's option parser (optimist 3.0.1) does with ``--verbose``.
    UNKNOWN_VERBOSE = Exit(
        255, stderr="Error: unknown argument '--verbose'.\nTry --help for help.\n"
    )

    def __init__(
        self,
        scan: Optional[Outcome] = None,
        *,
        by_template: Optional[Mapping[str, Outcome]] = None,
    ) -> None:
        """``scan`` answers every template; ``by_template`` answers the templates
        it names (the staged copy's file name), and the rest get the findings."""
        self.scan = scan
        self.by_template = dict(by_template or {})

    def run(self, call: ToolCall) -> Outcome:
        if "--verbose" in call.args:
            return self.UNKNOWN_VERBOSE
        parsed = self.GRAMMAR.parse(call)
        if parsed.last("--output-format") != "sarif":
            raise call.reject("ASH reads SARIF only")
        rules = parsed.last("--rule-directory")
        if rules is None or not Path(rules).is_dir():
            raise call.reject(f"--rule-directory {rules} is not a directory")
        template = parsed.last("--input-path")
        if template is None or not call.confined(template).is_file():
            raise call.reject(f"--input-path {template} is not a file")
        if call.cwd is None:
            raise call.reject("cfn_nag renders URIs against its working directory")
        if self.scan is not None:
            return self.scan
        if Path(template).name in self.by_template:
            return self.by_template[Path(template).name]
        report = json.loads(fixture("findings.sarif"))
        uri = os.path.relpath(template, os.path.realpath(call.cwd))
        results = report["runs"][0]["results"]
        for result in results:
            for location in result["locations"]:
                location["physicalLocation"]["artifactLocation"]["uri"] = uri
        # cfn_nag counts only failing violations (violation.rb); a warning is not one.
        failing = sum(1 for result in results if result.get("level") == "error")
        return Exit(failing, stdout=json.dumps(report, indent=2) + "\n")


def cfn_nag_config(**options) -> CfnNagScannerConfig:
    """The cfn-nag scanner's config with ``options``."""
    return CfnNagScannerConfig(options=CfnNagScannerConfigOptions(**options))


def cfn_nag_scan(char, config: Optional[CfnNagScannerConfig] = None, **kwargs):
    """The cfn-nag scanner run through the characterization harness ``char``, its
    clock fixed, the way ScanPhase runs it."""
    char.fix_clock()
    return char.run_scanner(CfnNagScanner, config or cfn_nag_config(), **kwargs)
