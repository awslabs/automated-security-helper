#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Scans the committed fixture with an installed ASH and checks the outcome:
#
#   scan-committed-fixture.sh <ash-bin> <fixture-dir> <work-dir>
#
# homebrew.sh runs it with the ASH the formula installed and
# tests/test_data/homebrew_scan (see its README.md): an S3 bucket with no
# encryption, logging or TLS-only policy for cdk-nag, which needs the formula's
# `cdk` extra and Node.js, and clean Python for bandit, which ASH installs with the
# keg's uv at scan time. The scan has to exit 2 (actionable findings), write
# ash_aggregated_results.json and reports/ash.sarif, and record cdk-nag FAILED and
# bandit PASSED. A scan that ran nothing exits 0, and would pass a fixture with no
# findings; this one has some.
#
# The fixture is copied out of the checkout first, so the scan reads only its own
# files and none of this repository's configuration. $PYTHON (default python3)
# reads the results. tests/unit/test_homebrew_macos_ci_job.py runs this script
# against a stand-in ash.
set -euo pipefail

usage="usage: scan-committed-fixture.sh <ash-bin> <fixture-dir> <work-dir>"
ASH_BIN="${1:?$usage}"
FIXTURE="${2:?$usage}"
WORK="${3:?$usage}"
PYTHON="${PYTHON:-python3}"

say() { printf '== %s\n' "$*"; }
fail() {
  printf '::error::%s\n' "$*" >&2
  exit 1
}

[ -d "$FIXTURE" ] || fail "no fixture directory at $FIXTURE"
src="$WORK/fixture"
out="$WORK/out-fixture"
mkdir -p "$WORK"
rm -rf "${src:?}" "${out:?}"
cp -R "$FIXTURE" "$src"

rc=0
"$ASH_BIN" scan --source-dir "$src" --output-dir "$out" --simple \
  --phases scan --phases report --scanners cdk-nag --scanners bandit || rc=$?
[ "$rc" -eq 2 ] || fail "the scan of the committed fixture exited $rc, expected 2 (cdk-nag's findings on template.yaml)"

results="$out/ash_aggregated_results.json"
[ -s "$results" ] || fail "the scan of the committed fixture wrote no $results"
[ -s "$out/reports/ash.sarif" ] || fail "the scan of the committed fixture wrote no $out/reports/ash.sarif"

statuses="$("$PYTHON" -c '
import json, sys
results = json.load(open(sys.argv[1], encoding="utf-8")).get("scanner_results", {})
print(" ".join(name + "=" + str((results.get(name) or {}).get("status")) for name in ("cdk-nag", "bandit")))
' "$results")"
[ "$statuses" = "cdk-nag=FAILED bandit=PASSED" ] ||
  fail "the scan of the committed fixture recorded $statuses, expected cdk-nag=FAILED bandit=PASSED"
say "committed fixture scan: exit 2, $statuses, results and SARIF report written"
