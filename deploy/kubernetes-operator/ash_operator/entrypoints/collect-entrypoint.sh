#!/bin/sh
# Collector wrapper: assemble an importable ash_operator package from the run's
# ConfigMap, then hand off to collect.py.
#
# The ConfigMap carries flat keys -- a ConfigMap key cannot contain "/" -- so the
# two-module package the collector imports has to be built here. Copying the
# operator's own source files rather than a second in-line copy is the point:
# ash_operator/attempts.py is one file in the repository, unit-tested there, and
# what runs in the cluster is that same file.
set -u

log() { printf '%s %s\n' "[ash-collect-boot]" "$*" >&2; }
die() { log "FATAL: $*"; exit 1; }

: "${ASH_CONFIG_MOUNT:?}"
PYLIB="${ASH_PYLIB_DIR:-/tmp/ash-operator-pylib}"

mkdir -p "${PYLIB}/ash_operator" || die "cannot create ${PYLIB}/ash_operator"
: >"${PYLIB}/ash_operator/__init__.py"
for module in constants attempts; do
  src="${ASH_CONFIG_MOUNT}/_${module}.py"
  [ -f "${src}" ] || die "${src} is missing from the ConfigMap mount"
  cp "${src}" "${PYLIB}/ash_operator/${module}.py" || die "cannot copy ${src}"
done
[ -f "${ASH_CONFIG_MOUNT}/collect.py" ] || die "collect.py is missing from the ConfigMap mount"

PYTHON="${ASH_PYTHON:-python3}"
command -v "${PYTHON}" >/dev/null 2>&1 || die "${PYTHON} is not on PATH in this image"

# PYTHONDONTWRITEBYTECODE because the ConfigMap mount is read-only and a failed
# .pyc write is noise in a log someone reads to diagnose a refusal.
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="${PYLIB}${PYTHONPATH:+:${PYTHONPATH}}" \
  "${PYTHON}" "${ASH_CONFIG_MOUNT}/collect.py" "$@"
COLLECT_EXIT=$?
log "collect.py exited ${COLLECT_EXIT}"

# Unlike a shard, the collector's exit code IS the verdict -- it is the only place
# in the run that has seen every shard.
exit ${COLLECT_EXIT}
