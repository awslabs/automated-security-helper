#!/bin/sh
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Downloads grype's and trivy's vulnerability databases for the ASH nix shell
# (flake.nix's shellHook runs it on every entry).
#
# Both tools look for a config file in their working directory when none is named
# (grype `.grype.yaml` and `.grype/config.yaml`, trivy `trivy.yaml`), and the shell
# hook runs wherever `nix develop` was started. So both run here from a fresh empty
# directory, each with an explicit empty config of this script's own, and the
# databases come from the tools' defaults wherever the shell was entered. This is
# what ASH's own database refresh does for scans (utils/content_db_refresh.py).
#
# Reads GRYPE_DB_CACHE_DIR and TRIVY_CACHE_DIR, which the shell hook sets. A failed
# download is reported and does not stop the shell.

set -u

workdir="$(mktemp -d "${TMPDIR:-/tmp}/ash-content-db.XXXXXX")" || {
    echo "ash: could not create a working directory; scanner databases not updated" >&2
    exit 0
}
trap 'rm -rf "$workdir"' EXIT
config="$workdir/empty-tool-config.yaml"
: > "$config"
cd "$workdir" || exit 0

# Announced rather than silent: these are network fetches inside what is otherwise
# a hermetic shell, and a reader deserves to know they happened.
if [ -z "$(ls -A "$GRYPE_DB_CACHE_DIR" 2>/dev/null)" ]; then
    echo "ash: seeding grype vulnerability database (one time, needs network)" >&2
    grype db update -c "$config" >/dev/null 2>&1 \
        || echo "ash: grype database download FAILED; grype will report ERROR" >&2
fi

# Refreshed on every entry, not only the first: nix mode scans offline, and ASH
# holds trivy's database to trivy's own 24-hour bound, so a database seeded once
# would fail every scan a day later. trivy returns at once when its database is
# current.
if [ -z "$(ls -A "$TRIVY_CACHE_DIR" 2>/dev/null)" ]; then
    echo "ash: seeding trivy vulnerability database (needs network)" >&2
fi
trivy image --download-db-only --no-progress --config "$config" \
    --cache-dir "$TRIVY_CACHE_DIR" >/dev/null 2>&1 \
    || echo "ash: trivy database update FAILED; trivy uses what is cached, or reports MISSING" >&2

exit 0
