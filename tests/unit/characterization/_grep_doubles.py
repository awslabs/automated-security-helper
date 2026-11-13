# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Doubles for semgrep and opengrep, whose CLIs ASH drives the same way.

``GrepScannerBase`` builds one argv for both tools, so one double serves both. Each
tool gets its own grammar: semgrep's is the flags ASH passes semgrep, and opengrep's
adds the ``--json`` and ``--pattern`` flags of opengrep's patterns mode. Any other
flag fails the test.

Also here: ``rules_cache`` for the offline tests.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import List, Optional

from tests.unit.characterization._harness import (
    FIXED_INSTANT,
    FIXTURES_DIR,
    PACKAGE_DIR,
    ArgvGrammar,
    Exit,
    Outcome,
    ToolCall,
    ToolDouble,
)

_COMMON_VALUE_FLAGS = frozenset(
    {"--config", "--metrics", "--exclude", "--exclude-rule", "--severity"}
)
_COMMON_BOOL_FLAGS = frozenset(
    {"--sarif", "--x-ignore-semgrepignore-files", "--no-rewrite-rule-ids"}
)

GRAMMARS = {
    "semgrep": ArgvGrammar(
        value_flags=_COMMON_VALUE_FLAGS | {"--sarif-output"},
        bool_flags=_COMMON_BOOL_FLAGS,
        min_positionals=2,
        max_positionals=2,
    ),
    "opengrep": ArgvGrammar(
        value_flags=_COMMON_VALUE_FLAGS | {"--sarif-output", "--pattern"},
        bool_flags=_COMMON_BOOL_FLAGS | {"--json"},
        min_positionals=2,
        max_positionals=2,
    ),
}

METRICS = frozenset({"auto", "on", "off"})
SEVERITIES = frozenset({"INFO", "WARNING", "ERROR"})
REGISTRY_PREFIXES = ("p/", "r/")


class GrepDouble(ToolDouble):
    """``semgrep scan`` or ``opengrep scan`` as ASH runs it, and ``--version``.

    Copies ``fixtures/<tool>/results.sarif`` to ``--sarif-output``, which both tools
    write in SARIF whatever else is asked for. With ``--json`` (opengrep's patterns
    mode) it also prints ``fixtures/<tool>/results.json`` on stdout, where the tools
    print their primary output. Each ``--config`` must be a registry name or an
    existing file or directory. Every path argv names goes through
    ``ToolCall.confined`` before anything probes it, so one outside the test's tree
    fails the test; a ``--config`` may also name ASH's bundled rules. Exits 0 by default:
    neither tool exits non-zero for findings unless asked to with ``--error``, which
    ASH does not pass.
    """

    def __init__(
        self,
        tool: str,
        scan: Optional[Outcome] = None,
        *,
        version: Optional[Outcome] = None,
        writes_output: bool = True,
    ) -> None:
        self.tool = tool
        self.grammar = GRAMMARS[tool]
        self.scan = scan
        self.version = version or Exit(
            0, stdout={"semgrep": "1.130.0\n", "opengrep": "1.30.2\n"}[tool]
        )
        self.writes_output = writes_output

    @staticmethod
    def _argv_path(call: ToolCall, value: str, *, assets: bool = False) -> Path:
        """``value`` as the tool reads it, relative to its cwd. ``call.confined``
        refuses it outside the test's tree, except that with ``assets`` a path under
        ASH's package (its bundled rules) is taken as it is."""
        if assets:
            path = Path(value)
            if not path.is_absolute():
                path = Path(call.cwd or os.getcwd()) / path
            if Path(os.path.normpath(path)).is_relative_to(PACKAGE_DIR):
                return path
        return call.confined(value)

    def run(self, call: ToolCall) -> Outcome:
        if call.args == ["--version"]:
            return self.version
        parsed = self.grammar.parse(call)
        subcommand, target = parsed.positionals
        if subcommand != "scan":
            raise call.reject(f"subcommand {subcommand!r}")
        if not self._argv_path(call, target).is_dir():
            raise call.reject(f"target {target} is not a directory")
        for value in parsed.flags.get("--metrics", []):
            if value not in METRICS:
                raise call.reject(f"--metrics {value}")
        for value in parsed.flags.get("--severity", []):
            if value not in SEVERITIES:
                raise call.reject(f"--severity {value}")
        configs: List[Optional[str]] = parsed.flags.get("--config", [])
        for value in configs:
            if value is None:
                raise call.reject("--config without a value")
            if value.startswith(REGISTRY_PREFIXES):
                continue
            if not self._argv_path(call, value, assets=True).exists():
                raise call.reject(f"--config {value} is neither a ruleset nor a path")
        if parsed.has("--pattern") and configs:
            raise call.reject("--pattern together with --config")
        outputs = parsed.flags.get("--sarif-output", [])
        if len(outputs) != 1:
            raise call.reject(f"expected one --sarif-output, got {outputs}")
        if self.writes_output:
            output = self._argv_path(call, str(outputs[0]))
            if not output.parent.is_dir():
                raise call.reject(
                    f"the directory of --sarif-output {output} is missing"
                )
            call.write_fixture(f"{self.tool}/results.sarif", output)
        outcome = self.scan if self.scan is not None else Exit(0)
        if parsed.has("--json") and isinstance(outcome, Exit):
            json_text = (FIXTURES_DIR / self.tool / "results.json").read_text(
                encoding="utf-8"
            )
            outcome = Exit(
                outcome.returncode, json_text + outcome.stdout, outcome.stderr
            )
        return outcome


#: How old the rules in ``rules_cache`` are at ``FIXED_INSTANT``: inside the 30-day
#: bound ASH holds an offline ruleset to, so the scan records it as fresh.
RULES_AGE_DAYS = 10


def rules_cache(directory: Path, rules: bool = True, suffix: str = ".yml") -> Path:
    """An offline rules cache: one rules file named ``p-ci<suffix>``, dated
    ``RULES_AGE_DAYS`` before ``FIXED_INSTANT``, or none when ``rules`` is false.

    ASH records the cache's age in the SARIF it writes, so a scan that reads it
    needs ``char.fix_clock()``; the modules' ``_with_rules_cache`` calls it.
    """
    directory.mkdir(parents=True, exist_ok=True)
    if rules:
        path = directory / f"p-ci{suffix}"
        path.write_text(
            "rules:\n"
            "  - id: eval-detected\n"
            "    pattern: eval(...)\n"
            "    message: eval\n"
            "    languages: [python]\n"
            "    severity: WARNING\n",
            encoding="utf-8",
        )
        then = FIXED_INSTANT.timestamp() - RULES_AGE_DAYS * 86400
        os.utime(path, (then, then))
    return directory
