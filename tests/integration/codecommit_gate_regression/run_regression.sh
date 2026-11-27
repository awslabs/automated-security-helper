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
# Set KEEP_WORKDIR=1 to retain the scratch trees for inspection. A run in which a
# case produced no result keeps them without it, because the log the failure message
# names is in them.

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

# What the image's /bin/sh runs for one scan, with the destination commit as $1.
#
# It mirrors CODECOMMIT_GATE_HANDLER's argv, including how it names the directory:
# `ash scan fs PATH` when the image's ASH has the `fs` subject (3.9 and later, whose
# help names `scan fs`), and `--source-dir PATH` when it does not. As in the handler,
# only an answer picks the older spelling: a help that does not name `scan fs`, or a
# usage error that refuses the word `fs`. A probe that fails any other way (a crash,
# an out-of-memory kill) says nothing about the image's ASH, so the script exits 70
# with the end of the probe's output BEFORE it prints the ASH_EXIT marker. 70 is not one
# of ASH's own exit codes, so docker's status, which is the script's, tells a check that
# got no answer from a scan that ran. The caller then reports that ash never ran, with
# the diagnosis in the log, instead of scoring a scan that used a spelling chosen by
# guess.
#
# A quoted heredoc: this shell expands none of it. `read -d ''` takes the whole text and
# returns non-zero at the end of it, which is why `|| true` follows.
IFS= read -r -d '' INNER_SCAN <<'SH' || true
cd /work/src || exit 70
probe_status=0
probe_help="$(ash scan fs --help 2>&1)" || probe_status=$?
case "$probe_status:$probe_help" in
  0:*"scan fs"*)
    directory="fs /work/src"
    echo "ash: scanning with 'ash scan fs': its help names 'scan fs'" >&2 ;;
  0:*)
    directory="--source-dir /work/src"
    echo "ash: scanning with the older spelling: the help of 'ash scan fs --help' does not name 'scan fs', as an ASH older than 3.9 answers" >&2 ;;
  *:*"unexpected extra argument"*"fs"*|*:*"No such command"*"fs"*)
    directory="--source-dir /work/src"
    echo "ash: scanning with the older spelling: this ASH refused the word 'fs', as an ASH older than 3.9 does" >&2 ;;
  *)
    echo "ash: could not tell whether this ASH has 'ash scan fs': 'ash scan fs --help' exited $probe_status without saying it refused 'fs', so no spelling is chosen by guess. The end of its output:" >&2
    printf '%s\n' "$probe_help" | tail -n 20 >&2
    exit 70 ;;
esac
# $directory is two words on purpose: `fs PATH` or `--source-dir PATH`.
ash scan $directory --output-dir /work/out \
  --no-progress --simple --compact-report --changed-files-only --base-ref "$1" \
  --min-severity medium
echo "ASH_EXIT=$?"
SH

# Runs one scan in the image and sets two variables. They are set here, not printed,
# because a command substitution would lose the second.
#   SCAN_CODE      ASH's exit code, read from the marker the inner script echoes;
#                  empty when there is no marker, which means ash never ran.
#   DOCKER_STATUS  docker's own status, which is the inner script's: 70 when its check
#                  of which spelling the image's ASH takes got no answer.
run_scan() {
  local repo="$1" out="$2" dest="$3" log="$4"
  mkdir -p "$out"
  chmod 777 "$out"
  # ASH's own status travels in the marker, not in docker's, so a non-zero docker
  # status must not stop the script. It is kept, because without it a docker failure
  # and a check that got no answer would read the same. A missing marker is treated
  # as a failure below rather than as success.
  DOCKER_STATUS=0
  docker run --rm --entrypoint /bin/sh \
    -e GIT_CONFIG_COUNT=1 -e GIT_CONFIG_KEY_0=safe.directory -e GIT_CONFIG_VALUE_0='*' \
    -v "$repo:/work/src" -v "$out:/work/out" \
    "$IMAGE" -c "$INNER_SCAN" sh "$dest" > "$log" 2>&1 || DOCKER_STATUS=$?
  SCAN_CODE="$(sed -n 's/^ASH_EXIT=\([0-9]\+\).*/\1/p' "$log" | tail -1)"
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

  run_scan "$repo" "$out" "$dest" "$log"
  code="$SCAN_CODE"
  if [ -z "$code" ]; then
    echo "FAIL: the container produced no ASH_EXIT marker; ash never ran."
    echo "      docker exited $DOCKER_STATUS"
    # Only the scan script gives 70, so the hint is for 70 alone: any other status is
    # docker's or the kernel's (125 docker could not run it, 137 the container was
    # killed), and a hint about the check would send the reader to the wrong place.
    if [ "$DOCKER_STATUS" -eq 70 ]; then
      echo "      70 is the status the scan script ends with when it cannot tell which"
      echo "      spelling this image's ASH takes, or cannot enter its source mount:"
      echo "      no scan ran, and the log says which"
    fi
    echo "      full log: $log"
    # 21 lines: the check's own line, which names the command it asked about, and the
    # 20 lines of its output that follow it. A shorter tail cuts the line off.
    echo "      last lines of $log:"
    tail -21 "$log" | sed 's/^/        /'
    # Keep the log: a run that never ran has nothing else to show why, and the
    # default run deletes the directory it is in.
    KEEP_WORKDIR=1
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
  #
  # The mapping comes from gate-contract.json, which gate_contract.py DERIVES by
  # calling the gate's own _verdict(). It used to be read from a hand-typed copy
  # in expected.json that stopped at exit code 3, so a run that exited 4 was
  # scored by the `.get` default rather than by the gate's logic -- the same
  # answer here, by luck, and not the gate's answer.
  VERDICTS[$case_name]="$(python3 -c "
import json
contract = json.load(open('$HERE/gate-contract.json'))
mapping = contract['verdict_mapping']
print(mapping.get('$code', mapping['unknown']))
")"
  echo "  full ASH output: $log"
  echo
done

echo "--- cross-case divergence ---"
echo "vulnerable -> ${VERDICTS[vulnerable]:-<unset>}"
echo "clean      -> ${VERDICTS[clean]:-<unset>}"
if [ "${VERDICTS[vulnerable]:-<no-run>}" = "<no-run>" ] \
    || [ "${VERDICTS[clean]:-<no-run>}" = "<no-run>" ]; then
  # Two cases that never ran have the same non-verdict, which is not a divergence
  # check's finding; the run has already failed above.
  echo "NOT COMPARED: a case never ran, so there is no verdict to compare."
elif [ "${VERDICTS[vulnerable]:-a}" = "${VERDICTS[clean]:-b}" ]; then
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
