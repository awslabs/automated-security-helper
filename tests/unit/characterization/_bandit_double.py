# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The bandit double, its config and its uv route, as the cells share them.

``test_bandit`` pins how ASH launches bandit; the sandbox and harness cells and the
explicit-executor cells scan with the same double, source and route. They live here,
not in a test file, so no cell file has to import another to use them.
"""

from __future__ import annotations

from typing import Optional

from automated_security_helper.plugin_modules.ash_builtin.scanners.bandit_scanner import (
    BanditScannerConfig,
    BanditScannerConfigOptions,
)
from tests.unit.characterization._harness import (
    ArgvGrammar,
    Exit,
    Outcome,
    ToolCall,
    ToolDouble,
    UvDouble,
)

SOURCE = {"app.py": "assert True\n"}


class BanditDouble(ToolDouble):
    """bandit's CLI, as far as ASH uses it.

    Writes the fixture for the format bandit would write to ``--output``: the last
    ``--format`` given, because bandit declares ``--format`` with argparse's
    ``store`` action. Exits 1 by default, as bandit does when it reports an issue
    and the fixture holds one.
    """

    GRAMMAR = ArgvGrammar(
        value_flags=frozenset(
            {
                "--format",
                "--output",
                "--confidence-level",
                "--severity-level",
                "--ini",
                "--configfile",
            }
        ),
        bool_flags=frozenset({"--recursive", "--verbose", "--ignore-nosec"}),
        glued_flags=frozenset({"--exclude"}),
        min_positionals=1,
    )
    FORMAT_FIXTURES = {"sarif": "results.sarif", "json": "results.json"}
    LEVELS = frozenset({"all", "low", "medium", "high"})

    def __init__(
        self,
        scan: Optional[Outcome] = None,
        *,
        writes_output: bool = True,
        version: str = "bandit 1.8.6\n  python version = 3.12.0\n",
    ) -> None:
        self.scan = scan
        self.writes_output = writes_output
        self.version = version

    def run(self, call: ToolCall) -> Outcome:
        if call.args == ["--version"]:
            return Exit(0, stdout=self.version)
        parsed = self.GRAMMAR.parse(call)
        for flag in ("--confidence-level", "--severity-level"):
            for value in parsed.flags.get(flag, []):
                if value not in self.LEVELS:
                    raise call.reject(f"{flag} {value}")
        for target in parsed.positionals:
            if not call.confined(target).exists():
                raise call.reject(f"target {target} does not exist")
        for flag in ("--ini", "--configfile"):
            value = parsed.last(flag)
            if value is not None and not call.confined(value).is_file():
                raise call.reject(f"{flag} {value} is not a file")
        if self.writes_output:
            output = parsed.last("--output")
            fmt = (parsed.flags.get("--format") or ["screen"])[-1]
            if output is None or fmt not in self.FORMAT_FIXTURES:
                raise call.reject(f"no fixture for --format {fmt} --output {output}")
            if not call.confined(output).parent.is_dir():
                raise call.reject(f"the directory of --output {output} does not exist")
            call.write_fixture(f"bandit/{self.FORMAT_FIXTURES[fmt]}", output)
        return self.scan if self.scan is not None else Exit(1)


def _config(**options) -> BanditScannerConfig:
    return BanditScannerConfig(options=BanditScannerConfigOptions(**options))


def _uv_route(char, bandit: Optional[BanditDouble] = None, **uv) -> None:
    """uv on PATH, with bandit installed as a uv tool and nowhere else."""
    char.absent("bandit")
    char.tool("uv", UvDouble(installed=["bandit"], **uv))
    char.tool("bandit", bandit or BanditDouble(), on=None)
    char.write_source(SOURCE)
