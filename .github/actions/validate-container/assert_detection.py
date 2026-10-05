# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Require the planted defects back, by rule id, from a detection-fixture scan.

Run with:
    python3 assert_detection.py RESULTS_JSON

Why this checks rule ids and not per-scanner counts
---------------------------------------------------
The detection fixture in validate-container plants two defects: a
``subprocess.call(cmd, shell=True)`` for bandit and a key-shaped credential for
detect-secrets. An earlier version of this check required each scanner to report
at least one actionable finding. That floor was met by findings that have nothing
to do with the plants. Measured: with ``shell=True`` removed from the fixture,
bandit still reports 3 findings (B404 for ``import subprocess``, B105 for the
credential assignment, B603 for the call without a shell), so the count check
stayed green while the defect it claimed to require was gone.

So each scanner is now required to report a specific rule for its plant:

* bandit: ``B602`` (subprocess call with ``shell=True``).
* detect-secrets: any ``SECRET-*`` rule. ASH prefixes every detect-secrets rule id
  with ``SECRET-``. The fixture currently trips three of them
  (``SECRET-AWS-ACCESS-KEY``, ``SECRET-SECRET-KEYWORD`` and
  ``SECRET-BASE64-HIGH-ENTROPY-STRING``), and which plugin fires is detect-secrets'
  business, so the prefix is required rather than one exact plugin.

The rule ids are read from the aggregated SARIF (``sarif.runs[].results[]``,
``ruleId`` and ``properties.scanner_name``). A result with a non-empty
``suppressions`` list is not counted: a suppression rule that grew to cover the
fixture would otherwise keep this green while the findings stopped reaching anyone.

Failure modes this does not cover
---------------------------------
* It does not check findings beyond the two plants. A scanner that lost every
  other rule would still pass here; the clean-fixture leg and the scanner unit
  tests are where that shows.
* If bandit renumbers B602 or ASH changes the ``SECRET-`` prefix, this fails. That
  is deliberate: the failure names the rule it expected, so updating the
  expectation is a one-line change made by someone who has read why it changed.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

# scanner name -> (description of the plant, predicate over a rule id, what is expected)
EXPECTED = {
    "bandit": (
        "the shell=True subprocess call",
        lambda rule_id: rule_id == "B602",
        "B602",
    ),
    "detect-secrets": (
        "the hardcoded credential",
        lambda rule_id: rule_id.startswith("SECRET-"),
        "a SECRET-* rule",
    ),
}


def actionable_rule_ids(data: dict[str, Any]) -> dict[str, set[str]]:
    """Map scanner name -> rule ids of its unsuppressed SARIF results.

    Raises ValueError when the report does not carry SARIF results in the expected
    shape, so a format change fails loudly instead of reading as "nothing found".
    """
    sarif = data.get("sarif")
    if not isinstance(sarif, dict) or not isinstance(sarif.get("runs"), list):
        raise ValueError("the report has no sarif.runs list")
    found: dict[str, set[str]] = {}
    for run in sarif["runs"]:
        if not isinstance(run, dict):
            continue
        for result in run.get("results") or []:
            if not isinstance(result, dict):
                continue
            if result.get("suppressions"):
                continue
            rule_id = result.get("ruleId")
            props = result.get("properties") or {}
            scanner = props.get("scanner_name") if isinstance(props, dict) else None
            if isinstance(rule_id, str) and isinstance(scanner, str):
                found.setdefault(scanner, set()).add(rule_id)
    return found


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("usage: assert_detection.py RESULTS_JSON", file=sys.stderr)
        return 2
    results = Path(argv[0])
    if not results.is_file() or results.stat().st_size == 0:
        listing = (
            sorted(p.name for p in results.parent.glob("*"))
            if results.parent.is_dir()
            else "(no output directory)"
        )
        print(
            f"FAIL: no usable results at {results}; the detection scan produced no "
            f"report. Output dir holds: {listing}",
            file=sys.stderr,
        )
        return 1

    try:
        found = actionable_rule_ids(json.loads(results.read_text(encoding="utf-8")))
    except (ValueError, AttributeError) as exc:
        print(
            f"FAIL: could not read rule ids from {results}: {exc}. The report "
            "changed shape, so nothing here was measured.",
            file=sys.stderr,
        )
        return 1

    for scanner in sorted(found):
        print(f"  {scanner:<18} {', '.join(sorted(found[scanner]))}")

    missing = []
    for scanner, (plant, matches, wanted) in EXPECTED.items():
        rule_ids = found.get(scanner, set())
        if not any(matches(r) for r in rule_ids):
            got = ", ".join(sorted(rule_ids)) or "nothing"
            missing.append(
                f"{scanner} did not report {wanted} for {plant} (got: {got})"
            )

    if missing:
        print(
            "FAIL: the image did not detect the planted defects: "
            + "; ".join(missing)
            + ". Findings from other rules do not count; each scanner must report "
            "the rule for its own plant.",
            file=sys.stderr,
        )
        return 1

    print(
        f"PASS: {', '.join(f'{s} {w}' for s, (_, _, w) in EXPECTED.items())} reported"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
