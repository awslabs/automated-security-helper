# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Clean audit reports as npm, pnpm and yarn write them, for stand-ins of the tools.

npm-audit accepts a report only with evidence the tool evaluated the lockfile:
findings under the tool's own report key, or the metadata block every real clean
report writes. Each tool has its own shape, so a stand-in answers the tool it
stands in for with that tool's report:

- npm 7 and later: ``vulnerabilities`` and a ``metadata`` block that counts the
  advisories and the dependencies (npm 10.9.4's clean output);
- pnpm: npm's v1 shape, ``advisories`` and ``metadata`` (the repository's capture
  of a real run, tests/test_data/scanners/npmaudit/pnpm/clean.json);
- yarn 1: NDJSON events, a clean report closed by one ``auditSummary`` line
  (the capture tests/test_data/scanners/npmaudit/yarn/classic-clean.json,
  yarn 1.22.22);
- yarn 2 and 3: one npm v1 document even when clean (the capture
  tests/test_data/scanners/npmaudit/yarn/berry3-clean.json, yarn 3.8.7).
  yarn 4 prints nothing at all for a clean audit and exits 0
  (yarn/berry-clean.json, yarn 4.18.1), so a yarn 4 stand-in answers empty
  stdout with exit 0 and needs no constant here.
"""

from __future__ import annotations

import json
from pathlib import Path

_CAPTURES = Path(__file__).resolve().parents[1] / "test_data" / "scanners" / "npmaudit"

#: What ``npm audit --json`` (npm 10.9.4) prints for a project with no advisories.
NPM_CLEAN = json.dumps(
    {
        "auditReportVersion": 2,
        "vulnerabilities": {},
        "metadata": {
            "vulnerabilities": {
                "info": 0,
                "low": 0,
                "moderate": 0,
                "high": 0,
                "critical": 0,
                "total": 0,
            },
            # npm counts the root package itself as prod, so one prod
            # dependency prints prod 2 / total 1, as the real capture shows.
            "dependencies": {
                "prod": 2,
                "dev": 0,
                "optional": 0,
                "peer": 0,
                "peerOptional": 0,
                "total": 1,
            },
        },
    }
)

#: What ``pnpm audit --json`` printed for a project with no advisories, captured.
PNPM_CLEAN = json.loads(
    (_CAPTURES / "pnpm" / "clean.json").read_text(encoding="utf-8")
)["stdout"]

#: What ``yarn audit --json`` (yarn 1.22.22) printed for a project with no
#: advisories, captured: NDJSON, the clean report closed by ``auditSummary``.
YARN_1_NO_ADVISORIES = json.loads(
    (_CAPTURES / "yarn" / "classic-clean.json").read_text(encoding="utf-8")
)["stdout"]

#: What ``yarn npm audit --json`` (yarn 3.8.7) printed for a project with no
#: advisories, captured: one npm v1 document, advisories and metadata.
YARN_BERRY_NO_ADVISORIES = json.loads(
    (_CAPTURES / "yarn" / "berry3-clean.json").read_text(encoding="utf-8")
)["stdout"]
