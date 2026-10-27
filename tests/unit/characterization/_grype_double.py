# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The grype double, and the routes and scan that use it, the cells share.

``test_grype`` pins how ASH launches grype; the trivy cells reuse its pass-through
sandbox backend, and the explicit-executor cells reuse its double, its routes and its
scan with the clock stopped. They live here, not in a test file, so no cell file has to
import another to use them.
"""

from __future__ import annotations

import json
from datetime import timedelta
from typing import Any, Dict, Optional, Sequence

from automated_security_helper.plugin_modules.ash_builtin.scanners.grype_scanner import (
    GrypeScanner,
    GrypeScannerConfig,
    GrypeScannerConfigOptions,
)
from automated_security_helper.utils.sandbox.backends import SandboxBackend, SpawnPlan
from tests.unit.characterization._harness import (
    FIXED_INSTANT,
    ArgvGrammar,
    Exit,
    Outcome,
    ToolCall,
    ToolDouble,
)

SOURCE = {"requirements.txt": "requests==2.0.0\n"}


def _before_the_fixed_clock(age: timedelta) -> str:
    """A build time ``age`` before ``FIXED_INSTANT``, where every scan's clock stops."""
    return (FIXED_INSTANT - age).strftime("%Y-%m-%dT%H:%M:%SZ")


class GrypeDouble(ToolDouble):
    """grype's CLI, as far as ASH uses it.

    A scan (``--output sarif --file F [--config C] dir:<target>``) copies the SARIF
    fixture to ``F`` and exits 0, as grype does without ``--fail-on``. ``db status -o
    json`` prints the database's build time (``built``): one hour before
    ``FIXED_INSTANT`` unless the scenario names one, or nothing at all with
    ``built=""``. ``db update -c C`` returns ``update``.
    """

    SCAN = ArgvGrammar(
        value_flags=frozenset({"--output", "--file", "--config"}),
        min_positionals=1,
        max_positionals=1,
    )
    DB_STATUS = ArgvGrammar(value_flags=frozenset({"-o"}), max_positionals=0)
    DB_UPDATE = ArgvGrammar(value_flags=frozenset({"-c"}), max_positionals=0)

    def __init__(
        self,
        scan: Optional[Outcome] = None,
        *,
        writes_output: bool = True,
        built: Optional[str] = None,
        status_returncode: int = 0,
        update: Outcome = Exit(0, stdout="Vulnerability database updated\n"),
    ) -> None:
        self.scan = scan
        self.writes_output = writes_output
        self.built = built
        self.status_returncode = status_returncode
        self.update = update

    def run(self, call: ToolCall) -> Outcome:
        if call.args[:2] == ["db", "status"]:
            parsed = self.DB_STATUS.parse(call, call.args[2:])
            if parsed.last("-o") != "json":
                raise call.reject("db status without -o json")
            return self._status()
        if call.args[:2] == ["db", "update"]:
            parsed = self.DB_UPDATE.parse(call, call.args[2:])
            config = parsed.last("-c")
            if config is None or not call.confined(config).is_file():
                raise call.reject(f"db update -c {config} is not a file")
            return self.update
        parsed = self.SCAN.parse(call)
        if parsed.last("--output") != "sarif":
            raise call.reject(f"--output {parsed.last('--output')}")
        config = parsed.last("--config")
        if config is not None and not call.confined(config).is_file():
            raise call.reject(f"--config {config} is not a file")
        target = parsed.positionals[0]
        if not target.startswith("dir:") or not call.confined(target[4:]).is_dir():
            raise call.reject(f"target {target} is not dir:<an existing directory>")
        if self.writes_output:
            output = parsed.last("--file")
            if output is None or not call.confined(output).parent.is_dir():
                raise call.reject(f"--file {output} has no directory to write into")
            call.write_fixture("grype/results.sarif", output)
        return self.scan if self.scan is not None else Exit(0)

    def _status(self) -> Outcome:
        if self.built == "":
            return Exit(self.status_returncode, stderr="failed to load database\n")
        built = self.built or _before_the_fixed_clock(timedelta(hours=1))
        status = {"built": built, "schemaVersion": "v6.0.2", "valid": True}
        return Exit(self.status_returncode, stdout=json.dumps(status) + "\n")


class PassThroughBackend(SandboxBackend):
    """A scanner sandbox backend that hands every spawn back unchanged.

    Stands in for bwrap so a sandbox scope is active without the wrapping: the
    golden then shows what grype changes under a sandbox, and nothing the backend
    adds.
    """

    name = "pass-through"
    platforms = ("linux", "darwin")

    def _probe(self) -> Optional[str]:
        return None

    def plan(self, argv: Sequence[str], env: Any, policy: Any) -> SpawnPlan:
        return SpawnPlan(argv=list(argv), env=dict(env))


def _config(**options) -> GrypeScannerConfig:
    return GrypeScannerConfig(options=GrypeScannerConfigOptions(**options))


def _grype(char, double: Optional[GrypeDouble] = None, **placement: Any) -> None:
    """Declare grype, a Go binary: its stand-in has no ``#!`` line."""
    char.tool("grype", double, interpreter=None, **placement)


def _path_route(char, grype: Optional[GrypeDouble] = None) -> None:
    _grype(char, grype or GrypeDouble())
    char.write_source(SOURCE)


def _offline(char) -> None:
    char.set_env(ASH_OFFLINE="YES")


def _scan(char, config=None, **kwargs) -> Dict[str, Any]:
    """Run grype's scan with the clock stopped, so the age records hold no run time."""
    char.fix_clock()
    return char.run_scanner(GrypeScanner, config or _config(), **kwargs)
