#!/bin/sh
# One shard of a sharded ASH scan.
#
# Mounted read-only from the run's ConfigMap and run as `sh <this file>`, so the
# ASH image needs no modification -- which matters because ASH publishes no image
# to any public registry and every adopter builds their own.
#
# Three properties this script exists to hold, each of which fails silently if
# it is dropped:
#
#   1. The results FILE, not the exit code, is the liveness test. Exit 2 from a
#      usage error -- an unrecognized --no-fail-on-findings on an older ASH, say --
#      is indistinguishable from exit 2 for findings.
#   2. This pod exits 0 even when the scan found something. A shard never owns the
#      verdict, and exiting non-zero for findings makes the Job controller retry a
#      shard that succeeded.
#   3. The published result directory is immutable and attempt-qualified. A retry
#      of this index must not be able to overwrite a completed attempt. See
#      ash_operator/attempts.py for what that does and does not guarantee.
#
# Deliberately not `set -e`: the scan is expected to exit non-zero and every
# failure below is checked explicitly. Under `set -e` the `ashx scan` line would
# end the script before the liveness check ran, and the pod would fail with the
# scan's exit code -- which is the one number that cannot be interpreted.
set -u

log() { printf '%s %s\n' "[ash-shard]" "$*" >&2; }
die() { log "FATAL: $*"; exit 1; }

# JOB_COMPLETION_INDEX is injected by the Job controller into every pod of an
# `Indexed` Job. Read here, in the shell, rather than referenced as
# `$(JOB_COMPLETION_INDEX)` from another env var's value: `$(VAR)` in a manifest
# resolves only against variables defined earlier in the same container's list,
# and the Job controller appends this one, so the reference would stay a literal
# string and `ashx scan` would be handed it where it wants an integer.
ASH_SHARD_INDEX="${ASH_SHARD_INDEX:-${JOB_COMPLETION_INDEX:-}}"
: "${ASH_SHARD_INDEX:?neither ASH_SHARD_INDEX nor JOB_COMPLETION_INDEX is set; the Job is not completionMode: Indexed}"
: "${ASH_SHARD_COUNT:?ASH_SHARD_COUNT is unset}"
: "${ASH_SOURCE_MOUNT:?}"
: "${ASH_OUTPUT_MOUNT:?}"
: "${ASH_RESULTS_PREFIX:?}"

# The attempt identity. The pod name of an Indexed Job pod is
# <job>-<index>-<random>: fixed within one attempt, different across retries.
ASH_ATTEMPT_ID="${ASH_ATTEMPT_ID:-${ASH_POD_NAME:-}}"
: "${ASH_ATTEMPT_ID:?neither ASH_ATTEMPT_ID nor ASH_POD_NAME is set; without a
per-attempt identity a retry publishes over a completed attempt and the collector
cannot tell}"
ASH_POD_UID="${ASH_POD_UID:-unknown}"

case "${ASH_SHARD_INDEX}" in
  ''|*[!0-9]*) die "ASH_SHARD_INDEX=${ASH_SHARD_INDEX} is not a non-negative integer" ;;
esac
case "${ASH_SHARD_COUNT}" in
  ''|*[!0-9]*) die "ASH_SHARD_COUNT=${ASH_SHARD_COUNT} is not a non-negative integer" ;;
esac
[ "${ASH_SHARD_COUNT}" -ge 1 ] || die "ASH_SHARD_COUNT must be at least 1"
[ "${ASH_SHARD_INDEX}" -lt "${ASH_SHARD_COUNT}" ] || die "ASH_SHARD_INDEX ${ASH_SHARD_INDEX} is not < ASH_SHARD_COUNT ${ASH_SHARD_COUNT}"

# --- 1. config ---------------------------------------------------------------
# ASH_CONFIG is the documented envvar form of `ashx scan --config`. When the CR
# carried no config block the operator does not create the file, and ASH_CONFIG
# must then be unset rather than pointing at a missing path, or every scan logs a
# missing-file notice that reads like a failure.
if [ -n "${ASH_CONFIG:-}" ] && [ ! -f "${ASH_CONFIG}" ]; then
  die "ASH_CONFIG=${ASH_CONFIG} does not exist. The operator sets this variable only
when it also writes the file, so this means the ConfigMap did not mount."
fi
if [ -n "${ASH_CONFIG:-}" ]; then
  log "using config ${ASH_CONFIG}"
else
  log "no config supplied; ASH defaults apply"
fi

[ -d "${ASH_SOURCE_MOUNT}" ] || die "source mount ${ASH_SOURCE_MOUNT} is not a directory"
mkdir -p "${ASH_OUTPUT_MOUNT}" || die "cannot create ${ASH_OUTPUT_MOUNT}"

# --- 2. scan -----------------------------------------------------------------
# Identical argv on every pod except the two integers. The partition is a pure
# function of (sorted, deduped, lower-cased scanner names, index, count), so pods
# never coordinate. Running `ashx scan` unmodified is what makes ScanPhase stamp
# candidate_scanners onto the results, which is the only check that can see a
# split-brain scanner roster.
#
# The two shard integers are appended HERE rather than baked into the Job's args.
# They are also the two flags an adopter may never supply, so appending them last
# means nothing earlier in the argv can have set them.
log "shard ${ASH_SHARD_INDEX} of ${ASH_SHARD_COUNT}, attempt ${ASH_ATTEMPT_ID}"
log "argv: $* --shard-index ${ASH_SHARD_INDEX} --shard-count ${ASH_SHARD_COUNT}"
"$@" --shard-index "${ASH_SHARD_INDEX}" --shard-count "${ASH_SHARD_COUNT}"
ASH_EXIT=$?
log "ashx scan exited ${ASH_EXIT}"

# --- 3. liveness -------------------------------------------------------------
printf '%s\n' "${ASH_EXIT}" >"${ASH_OUTPUT_MOUNT}/.shard-exit-code" 2>/dev/null || true
if [ ! -f "${ASH_OUTPUT_MOUNT}/ash_aggregated_results.json" ]; then
  log "shard ${ASH_SHARD_INDEX} produced no ash_aggregated_results.json"
  log "the scan's own exit code was ${ASH_EXIT}, which cannot distinguish findings"
  log "from a usage error, so the missing file is what this check reports"
  exit 1
fi

# --- 4. publish, attempt-qualified and immutable -----------------------------
ATTEMPT_ROOT="${ASH_RESULTS_PREFIX}/attempts/shard-${ASH_SHARD_INDEX}"
STAGING="${ATTEMPT_ROOT}/${ASH_ATTEMPT_ID}.partial"
PUBLISHED="${ATTEMPT_ROOT}/${ASH_ATTEMPT_ID}"

if [ -e "${PUBLISHED}" ]; then
  # Impossible unless two pods were handed the same attempt id, which would mean
  # the attempt identity is not per-attempt. Refuse rather than merge into it.
  die "${PUBLISHED} already exists. Attempt ids must be unique per pod attempt;
publishing into an existing one would overwrite a completed shard."
fi

mkdir -p "${ATTEMPT_ROOT}" || die "cannot create ${ATTEMPT_ROOT} -- is the results volume writable?"
rm -rf "${STAGING}"
mkdir -p "${STAGING}" || die "cannot create ${STAGING}"

# cp -R rather than mv: the output mount is a different volume from the results
# mount, so mv would fall back to copy-and-unlink anyway, and cp keeps the
# emptyDir intact for a debug container to look at.
cp -R "${ASH_OUTPUT_MOUNT}/." "${STAGING}/" || die "copy to ${STAGING} failed"
[ -f "${STAGING}/ash_aggregated_results.json" ] || die "copy left no results file in ${STAGING}"

DIGEST="$(sha256sum "${STAGING}/ash_aggregated_results.json" 2>/dev/null | cut -d' ' -f1)"
if [ -z "${DIGEST}" ]; then
  # No sha256sum in the image. Refuse rather than publish an unverifiable attempt:
  # the digest is what lets the collector tell a completed attempt from one a
  # retry truncated, and an attempt nobody can verify is the failure mode this
  # whole scheme exists to remove.
  die "sha256sum produced nothing. The collector verifies each published attempt
against this digest, so publishing without one would reintroduce the silent
overwrite the attempt-qualified layout prevents."
fi

# Written LAST inside the staging directory, so the published name never exists
# without its marker: the rename below is what makes it visible, and by then the
# marker is already inside.
cat >"${STAGING}/.attempt-complete" <<EOF
{"attemptId":"${ASH_ATTEMPT_ID}","podUid":"${ASH_POD_UID}","resultsSha256":"${DIGEST}","scanExitCode":${ASH_EXIT},"shardCount":${ASH_SHARD_COUNT},"shardIndex":${ASH_SHARD_INDEX}}
EOF

mv "${STAGING}" "${PUBLISHED}" || die "publish rename ${STAGING} -> ${PUBLISHED} failed"
log "published shard ${ASH_SHARD_INDEX} attempt ${ASH_ATTEMPT_ID} (sha256 ${DIGEST})"

# A worker NEVER owns the verdict.
exit 0
