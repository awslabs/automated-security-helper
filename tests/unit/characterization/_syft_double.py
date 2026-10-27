# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The syft double the characterization cells share.

``test_syft`` pins how ASH launches syft and ``test_grype`` scans an SBOM syft wrote;
both stand syft in with this double. It lives here, not in either test file, so one
cell file does not have to import another to use it.
"""

from __future__ import annotations

from typing import Optional

from tests.unit.characterization._harness import (
    ArgvGrammar,
    Exit,
    Outcome,
    ToolCall,
    ToolDouble,
)


class SyftDouble(ToolDouble):
    """syft's CLI, as far as ASH uses it.

    Every ``--output FORMAT=PATH`` gets that format's fixture written to ``PATH``; a
    format without ``=PATH`` would go to stdout, which ASH never asks for, so it is
    rejected. Exits 0 by default.
    """

    GRAMMAR = ArgvGrammar(
        value_flags=frozenset({"--output", "--base-path", "--config", "--exclude"}),
        min_positionals=1,
        max_positionals=1,
    )
    FORMAT_FIXTURES = {
        "cyclonedx-json": "syft.cdx.json",
        "cyclonedx-xml": "cyclonedx.xml",
        "github-json": "github.json",
        "spdx-json": "spdx.json",
        "spdx-tag-value": "spdx-tag-value.txt",
        "syft-json": "syft.json",
        "syft-table": "syft-table.txt",
        "syft-text": "syft-text.txt",
    }

    def __init__(
        self, scan: Optional[Outcome] = None, *, writes_output: bool = True
    ) -> None:
        self.scan = scan
        self.writes_output = writes_output

    def run(self, call: ToolCall) -> Outcome:
        parsed = self.GRAMMAR.parse(call)
        target = parsed.positionals[0]
        if not call.confined(target).exists():
            raise call.reject(f"target {target} does not exist")
        base = parsed.last("--base-path")
        if base is not None and not call.confined(base).is_dir():
            raise call.reject(f"--base-path {base} is not a directory")
        config = parsed.last("--config")
        if config is not None and not call.confined(config).is_file():
            raise call.reject(f"--config {config} is not a file")
        outputs = []
        for value in parsed.flags.get("--output", []):
            fmt, sep, path = (value or "").partition("=")
            if not sep or fmt not in self.FORMAT_FIXTURES:
                raise call.reject(f"--output {value}")
            if not call.confined(path).parent.is_dir():
                raise call.reject(f"--output {value} has no directory to write into")
            outputs.append((fmt, path))
        if self.writes_output:
            for fmt, path in outputs:
                call.write_fixture(f"syft/{self.FORMAT_FIXTURES[fmt]}", path)
        return self.scan if self.scan is not None else Exit(0)
