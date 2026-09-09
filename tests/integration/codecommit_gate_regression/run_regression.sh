#!/usr/bin/env bash
#
# Run the ASH pull-request gate regression pair against a container image.
#
# WHAT THIS PROVES
# ----------------
# Two pull-request-shaped scans, one carrying bandit HIGH findings and one clean,
# scanned with the gate's exact flag set. It passes only when both cases meet
# their expectations AND their verdicts differ. The divergence requirement is the
# point: on 2026-08-28 the gate reported "passed" on both, so either case alone
# looked defensible and only the pair exposed it.
#
# USAGE
#   ./run_regression.sh <image-ref> [workdir]
#
# The image must be an ASH image with the `ash` CLI on PATH. To test the gate as
# deployed, use the image the gate's Lambda actually runs:
#   aws ecr list-images --region <region> --repository-name <gate-ecr-repo>
#
# WHAT IT DOES NOT COVER
# ----------------------
# This exercises the SCAN half of the gate: the flags, ASH's exit code, and
# whether the scanners ran. It does not exercise EventBridge delivery, the
# CodeCommit clone over the `codecommit::` transport, comment posting, or the
# approval vote. Those need a deployed stack; see README.md for that procedure.
# A green run here does NOT mean the deployed gate works end to end.
#
# Set KEEP_WORKDIR=1 to retain the scratch trees for inspection.

set -euo pipefail

HERE_EARLY="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# The replay needs no image, no Docker and no AWS, so it runs first and runs
# even when this script is invoked with no arguments. It is the part of the
# fixture that works in a CI container with nothing installed.
echo "=== replay of the recorded observation (no image required) ==="
python3 "$HERE_EARLY/assert_case.py" --replay || REPLAY_SIGNAL=$?
echo

if [ "$#" -lt 1 ]; then
  echo "usage: $0 <image-ref> [workdir]" >&2
  echo "(the replay above ran; the live scan pair needs an image)" >&2
  exit 64
fi

IMAGE="$1"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKDIR="${2:-$(mktemp -d)}"
mkdir -p "$WORKDIR"

echo "image:   $IMAGE"
echo "workdir: $WORKDIR"
echo

# Build a two-commit repository shaped like the pull request: the base content on
# the destination branch, then the case's file on a feature branch. The gate
# diffs the feature tip against the destination commit, so the case file must be
# the ONLY thing the second commit adds.
build_repo() {
  local case_name="$1" branch="$2" repo="$3"
  mkdir -p "$repo"
  cp -R "$HERE/cases/base/." "$repo/"
  git -C "$repo" init -q -b main
  git -C "$repo" config user.email "gate-regression@example.invalid"
  git -C "$repo" config user.name "gate-regression"
  git -C "$repo" add -A
  git -C "$repo" commit -q -m "base"
  git -C "$repo" checkout -q -b "$branch"
  cp -R "$HERE/cases/$case_name/." "$repo/"
  git -C "$repo" add -A
  git -C "$repo" commit -q -m "$case_name"
  # The container runs as a different uid; make the tree readable to it.
  chmod -R a+rX "$repo"
}

# Returns ASH's exit code on stdout. Mirrors CODECOMMIT_GATE_HANDLER's argv.
run_scan() {
  local repo="$1" out="$2" dest="$3" log="$4"
  mkdir -p "$out"
  chmod 777 "$out"
  # `|| true` on docker itself would mask a container failure, so instead the
  # inner shell echoes ASH's own status and we parse that. A missing marker is
  # treated as a failure below rather than as success.
  docker run --rm --entrypoint /bin/sh \
    -e GIT_CONFIG_COUNT=1 -e GIT_CONFIG_KEY_0=safe.directory -e GIT_CONFIG_VALUE_0='*' \
    -v "$repo:/work/src" -v "$out:/work/out" \
    "$IMAGE" -c "cd /work/src && ash scan --source-dir /work/src --output-dir /work/out \
--no-progress --simple --compact-report --changed-files-only --base-ref $dest \
--min-severity medium; echo \"ASH_EXIT=\$?\"" > "$log" 2>&1 || true
  sed -n 's/^ASH_EXIT=\([0-9]\+\).*/\1/p' "$log" | tail -1
}

declare -A VERDICTS
OVERALL=0

for spec in "vulnerable:feat/unsafe-subprocess" "clean:feat/safe-math"; do
  case_name="${spec%%:*}"
  branch="${spec##*:}"
  repo="$WORKDIR/$case_name"
  out="$WORKDIR/$case_name-out"
  log="$WORKDIR/$case_name.log"

  echo "--- case: $case_name (branch $branch) ---"
  build_repo "$case_name" "$branch" "$repo"
  dest="$(git -C "$repo" rev-parse main)"

  code="$(run_scan "$repo" "$out" "$dest" "$log")"
  if [ -z "$code" ]; then
    echo "FAIL: the container produced no ASH_EXIT marker; ash never ran."
    echo "      last lines of $log:"
    tail -15 "$log" | sed 's/^/        /'
    OVERALL=1
    VERDICTS[$case_name]="<no-run>"
    echo
    continue
  fi

  if python3 "$HERE/assert_case.py" \
      --case "$case_name" \
      --aggregated "$out/ash_aggregated_results.json" \
      --sarif "$out/reports/ash.sarif" \
      --exit-code "$code"; then
    :
  else
    OVERALL=1
  fi
  # Record the verdict the gate would have derived, for the divergence check.
  VERDICTS[$case_name]="$(python3 -c "
import json,sys
m=json.load(open('$HERE/expected.json'))['verdict_mapping']
print(m.get('$code','errored'))
")"
  echo "  full ASH output: $log"
  echo
done

echo "--- cross-case divergence ---"
echo "vulnerable -> ${VERDICTS[vulnerable]:-<unset>}"
echo "clean      -> ${VERDICTS[clean]:-<unset>}"
if [ "${VERDICTS[vulnerable]:-a}" = "${VERDICTS[clean]:-b}" ]; then
  echo "FAIL: both cases produced the same verdict. A gate that returns one"
  echo "      verdict for every input is broken whichever verdict it picks."
  echo "      This is exactly the 2026-08-28 state (both 'passed')."
  OVERALL=1
else
  echo "PASS: verdicts diverge."
fi

if [ "${KEEP_WORKDIR:-0}" != "1" ] && [ "$#" -lt 2 ]; then
  rm -rf "$WORKDIR"
else
  echo
  echo "workdir retained: $WORKDIR"
fi

echo
# REPLAY_SIGNAL is non-empty only when the replay returned non-zero, which means
# XPASS -- the recorded observation no longer violates the invariant. That is good
# news needing an action (flip known_defect.expected_to_fail), so it is surfaced
# here rather than folded into the pair's own pass/fail.
if [ -n "${REPLAY_SIGNAL:-}" ]; then
  echo "NOTE: the replay reported XPASS. See its output above -- the exit-code fix"
  echo "      appears to have landed and expected.json needs its flag flipped."
fi

if [ "$OVERALL" -eq 0 ]; then
  echo "REGRESSION PAIR: PASS"
else
  echo "REGRESSION PAIR: FAIL"
fi
exit "$OVERALL"
