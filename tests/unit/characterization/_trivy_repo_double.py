# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The trivy double, and the routes and scan that use it, the cells share.

``test_trivy_repo`` pins how ASH launches trivy; the explicit-executor cells reuse its
double, its route, its scan with the clock stopped and its sandboxed context. They live
here, not in a test file, so no cell file has to import another to use them.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from automated_security_helper.plugin_modules.ash_trivy_plugins.trivy_repo_scanner import (
    TrivyRepoScanner,
    TrivyRepoScannerConfig,
    TrivyRepoScannerConfigOptions,
)
from tests.unit.characterization._grype_double import PassThroughBackend
from tests.unit.characterization._harness import (
    FIXED_INSTANT,
    ArgvGrammar,
    Exit,
    Outcome,
    ToolCall,
    ToolDouble,
)

SOURCE = {"requirements.txt": "requests==2.0.0\n"}

SCANNERS = frozenset({"vuln", "misconfig", "secret", "license"})
SEVERITIES = frozenset({"LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"})


class TrivyDouble(ToolDouble):
    """trivy's CLI, as far as ASH uses it.

    ``repository`` copies the SARIF fixture to ``--output`` and exits 0. ``version
    --format json`` reports a vulnerability database updated one hour before
    ``FIXED_INSTANT``, or at ``updated``, or none with ``database=False``. ``image
    --download-db-only`` and ``config`` of an empty directory (the database and
    checks-bundle refreshes) return ``update`` and ``checks``.
    """

    REPOSITORY = ArgvGrammar(
        value_flags=frozenset({"--format", "--scanners", "--severity", "--output"}),
        bool_flags=frozenset(
            {
                "--license-full",
                "--ignore-unfixed",
                "--disable-telemetry",
                "--skip-db-update",
                "--skip-java-db-update",
                "--skip-check-update",
                "--offline-scan",
            }
        ),
        glued_flags=frozenset({"--ignorefile", "--secret-config", "--cache-backend"}),
        min_positionals=1,
        max_positionals=1,
    )
    VERSION = ArgvGrammar(value_flags=frozenset({"--format"}), max_positionals=0)
    DOWNLOAD = ArgvGrammar(
        value_flags=frozenset({"--config", "--cache-dir"}),
        bool_flags=frozenset({"--download-db-only", "--no-progress"}),
        max_positionals=0,
    )
    CONFIG = ArgvGrammar(
        value_flags=frozenset({"--config", "--cache-dir"}),
        min_positionals=1,
        max_positionals=1,
    )

    def __init__(
        self,
        scan: Optional[Outcome] = None,
        *,
        writes_output: bool = True,
        database: bool = True,
        updated: Optional[datetime] = None,
        update: Outcome = Exit(0, stderr="Downloading vulnerability DB...\n"),
        checks: Outcome = Exit(0, stderr="Loaded the checks bundle\n"),
    ) -> None:
        self.scan = scan
        self.writes_output = writes_output
        self.database = database
        self.updated = updated
        self.update = update
        self.checks = checks

    def run(self, call: ToolCall) -> Outcome:
        subcommand, args = (call.args[0], call.args[1:]) if call.args else ("", [])
        if subcommand == "repository":
            return self._repository(call, args)
        if subcommand == "version":
            if self.VERSION.parse(call, args).last("--format") != "json":
                raise call.reject("version without --format json")
            return self._version()
        if subcommand == "image":
            parsed = self.DOWNLOAD.parse(call, args)
            self._check_refresh(call, parsed)
            if not parsed.has("--download-db-only"):
                raise call.reject("image without --download-db-only")
            return self.update
        if subcommand == "config":
            parsed = self.CONFIG.parse(call, args)
            self._check_refresh(call, parsed)
            if not call.confined(parsed.positionals[0]).is_dir():
                raise call.reject(f"config target {parsed.positionals[0]}")
            return self.checks
        raise call.reject(f"subcommand {subcommand!r}")

    @staticmethod
    def _check_refresh(call: ToolCall, parsed: Any) -> None:
        config = parsed.last("--config")
        if config is None or not call.confined(config).is_file():
            raise call.reject(f"--config {config} is not a file")
        if parsed.last("--cache-dir") is None:
            raise call.reject("a refresh without --cache-dir")

    def _repository(self, call: ToolCall, args: List[str]) -> Outcome:
        parsed = self.REPOSITORY.parse(call, args)
        if parsed.last("--format") != "sarif":
            raise call.reject(f"--format {parsed.last('--format')}")
        for flag, allowed in (("--scanners", SCANNERS), ("--severity", SEVERITIES)):
            value = parsed.last(flag)
            if value is not None and not set(value.split(",")) <= allowed:
                raise call.reject(f"{flag} {value}")
        for flag in ("--ignorefile", "--secret-config"):
            value = parsed.last(flag)
            if value is not None and not call.confined(value).is_file():
                raise call.reject(f"{flag}={value} is not a file")
        if parsed.last("--cache-backend") not in (None, "memory", "fs"):
            raise call.reject(f"--cache-backend={parsed.last('--cache-backend')}")
        target = parsed.positionals[0]
        if not call.confined(target).exists():
            raise call.reject(f"target {target} does not exist")
        if self.writes_output:
            output = parsed.last("--output")
            if output is None or not call.confined(output).parent.is_dir():
                raise call.reject(f"--output {output} has no directory to write into")
            call.write_fixture("trivy/results.sarif", output)
        return self.scan if self.scan is not None else Exit(0)

    def _version(self) -> Outcome:
        version: Dict[str, Any] = {"Version": "0.75.0"}
        if self.database:
            updated = self.updated or FIXED_INSTANT - timedelta(hours=1)
            version["VulnerabilityDB"] = {
                "Version": 2,
                "UpdatedAt": updated.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "NextUpdate": (updated + timedelta(days=1)).strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                ),
            }
        return Exit(0, stdout=json.dumps(version) + "\n")


def _config(**options) -> TrivyRepoScannerConfig:
    return TrivyRepoScannerConfig(options=TrivyRepoScannerConfigOptions(**options))


def _trivy(char, double: Optional[TrivyDouble] = None, **placement: Any) -> None:
    """Declare trivy, a Go binary: its stand-in has no ``#!`` line."""
    char.tool("trivy", double, interpreter=None, **placement)


def _path_route(char, trivy: Optional[TrivyDouble] = None) -> None:
    _trivy(char, trivy or TrivyDouble())
    char.write_source(SOURCE)


def _scan(char, config=None, **kwargs) -> Dict[str, Any]:
    """Run trivy-repo's scan with the clock stopped, so the age records hold no run time."""
    char.fix_clock()
    return char.run_scanner(TrivyRepoScanner, config or _config(), **kwargs)


def _sandboxed_context(char, monkeypatch):
    """A context whose config asks for the bwrap sandbox, with bwrap passing through."""
    from automated_security_helper.config.ash_config import AshConfig, SandboxConfig
    from automated_security_helper.utils.sandbox import backends

    monkeypatch.setitem(backends.BACKENDS, "bwrap", PassThroughBackend)
    return char.plugin_context(config=AshConfig(sandbox=SandboxConfig(mode="bwrap")))
