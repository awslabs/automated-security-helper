# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The doubles for npm, pnpm and yarn audits, with the projects and the config the cells
scan with.

They live here, and not in ``test_npm_audit``, so that the cells of other test files can
build the same world without importing a test file. This module imports nothing from one.
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional, Tuple

from automated_security_helper.plugin_modules.ash_builtin.scanners.npm_audit_scanner import (
    NpmAuditScannerConfig,
    NpmAuditScannerConfigOptions,
)
from tests.unit.characterization._harness import (
    FIXTURES_DIR,
    ArgvGrammar,
    Exit,
    Outcome,
    ToolCall,
    ToolDouble,
)

FIXTURES = FIXTURES_DIR / "npm-audit"


def _fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def _manifest(name: str) -> str:
    """The fixture for manifest or lockfile ``name``, committed as ``<name>.fixture``.

    The lockfiles resolve packages with real advisories (that is what the audit
    fixtures report). Under their own names, the repository's dependency graph and
    its own scans would parse them as this project's dependencies.
    """
    return _fixture(f"{name}.fixture")


def _project(lockfile: str, directory: str = "") -> Dict[str, str]:
    """A package.json, and beside it ``lockfile`` from the fixtures (none for "")."""
    prefix = f"{directory}/" if directory else ""
    files = {f"{prefix}package.json": _manifest("package.json")}
    if lockfile:
        files[f"{prefix}{lockfile}"] = _manifest(lockfile)
    return files


#: A project whose lockfile resolves the fixture advisories' packages.
NPM_PROJECT = _project("package-lock.json")


class AuditDouble(ToolDouble):
    """A package manager's audit, as far as ASH uses it.

    ``audit`` is what the audit prints and returns. The audit is refused unless its
    working directory holds ``lockfile``, because that is what the real tool reads,
    and refused for any flag ASH does not pass.
    """

    lockfile = ""
    AUDIT = ArgvGrammar()

    def __init__(
        self,
        audit: Optional[Outcome] = None,
        *,
        version: Outcome = Exit(0, stdout="10.9.2\n"),
    ) -> None:
        self.audit = audit
        self.version = version

    def default_audit(self) -> Outcome:
        raise NotImplementedError

    def audit_args(self, call: ToolCall) -> Tuple[ArgvGrammar, List[str]]:
        """The grammar for this audit's options, and the options."""
        if call.args[:2] != ["audit", "--json"]:
            raise call.reject("not an audit ASH runs")
        return self.AUDIT, call.args[2:]

    def run(self, call: ToolCall) -> Outcome:
        if call.args == ["--version"]:
            return self.version
        grammar, options = self.audit_args(call)
        grammar.parse(call, options)
        if call.cwd is None or not Path(call.cwd, self.lockfile).is_file():
            raise call.reject(f"no {self.lockfile} in the working directory {call.cwd}")
        return self.audit if self.audit is not None else self.default_audit()


class NpmDouble(AuditDouble):
    """npm; ``by_directory`` answers the audits run in the directories it names."""

    lockfile = "package-lock.json"
    AUDIT = ArgvGrammar(bool_flags=frozenset({"--offline"}))

    def __init__(
        self,
        audit: Optional[Outcome] = None,
        *,
        version: Outcome = Exit(0, stdout="10.9.2\n"),
        by_directory: Optional[Dict[str, Outcome]] = None,
    ) -> None:
        super().__init__(audit, version=version)
        self.by_directory = dict(by_directory or {})

    def run(self, call: ToolCall) -> Outcome:
        outcome = super().run(call)
        if call.args != ["--version"] and call.cwd is not None:
            return self.by_directory.get(Path(call.cwd).name, outcome)
        return outcome

    def default_audit(self) -> Outcome:
        return Exit(1, stdout=_fixture("npm.json"))


class PnpmDouble(AuditDouble):
    lockfile = "pnpm-lock.yaml"
    AUDIT = ArgvGrammar(bool_flags=frozenset({"--offline"}))

    def __init__(self, audit=None, *, version=Exit(0, stdout="9.15.0\n")) -> None:
        super().__init__(audit, version=version)

    def default_audit(self) -> Outcome:
        return Exit(1, stdout=_fixture("pnpm.json"))


class YarnDouble(AuditDouble):
    """yarn 1 (``yarn audit``) or, from 2, berry (``yarn npm audit``), by ``major``."""

    lockfile = "yarn.lock"
    CLASSIC = ArgvGrammar(bool_flags=frozenset({"--offline"}))
    # `yarn npm audit` rejects --offline; only --recursive is passed.
    BERRY = ArgvGrammar(bool_flags=frozenset({"--recursive"}))

    def __init__(self, major: int = 1, audit=None, *, version=None) -> None:
        printed = {1: "1.22.22\n", 2: "2.4.3\n", 3: "3.8.7\n", 4: "4.5.3\n"}[major]
        super().__init__(audit, version=version or Exit(0, stdout=printed))
        self.major = major

    def audit_args(self, call: ToolCall) -> Tuple[ArgvGrammar, List[str]]:
        if self.major < 2:
            if call.args[:2] != ["audit", "--json"]:
                raise call.reject("yarn 1 audits with `yarn audit`")
            return self.CLASSIC, call.args[2:]
        if call.args[:3] != ["npm", "audit", "--json"]:
            raise call.reject("yarn 2+ audits with `yarn npm audit`")
        return self.BERRY, call.args[3:]

    def default_audit(self) -> Outcome:
        if self.major < 2:
            # yarn 1's exit status is a bitmask of the severities found; 16 is critical.
            return Exit(16, stdout=_fixture("yarn1.ndjson"))
        if self.major < 4:
            # yarn 2 and 3 relay the registry's npm v1 audit document.
            return Exit(1, stdout=_fixture("yarn3.json"))
        return Exit(1, stdout=_fixture("yarn4.ndjson"))


def _config(**options) -> NpmAuditScannerConfig:
    return NpmAuditScannerConfig(options=NpmAuditScannerConfigOptions(**options))
