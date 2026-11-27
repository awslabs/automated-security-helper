#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# A real scan through the plugin as the IDE's installer unpacked it from the zip, headless:
#
#   bash editors/jetbrains/e2e-installed-scan.sh <ide-cycle-work-dir> <real-cli-work-dir>
#
# Runs after e2e-ide-cycle.sh and e2e-real-cli.sh, and reads what they left:
#   <ide-cycle-work-dir>/installed-plugins.env   the fresh N install and a separate N-1 install
#   <real-cli-work-dir>/venv/bin                 ashx and ash, installed from the head wheel
#
# WHY. realCliTest scans through the plugin the build put in its own sandbox, and the IDE cycle
# installs the zip but only checks which version the IDE says it loaded. Neither runs the
# installed artifact. This runs the installedZipTest task (build.gradle.kts): AshLoadedPluginTest,
# which requires the plugin loaded from the installed directory, at N, with its classes from
# that directory's jar, and then the real-CLI findings case (exit 2, 3 highlights, judged by
# scripts/e2e/assert_outcome.py) through that plugin.
#
# 1. The installed files are still byte-identical to their zips.
# 2. Negative control first: the same task pointed at the N-1 install while expecting N must
#    fail, and fail on the loaded version. That is what shows the check reads the installed
#    plugin rather than the build's.
# 3. The task against the N install, and its census (assertInstalledZipTestsRan).
#
# Nothing is published.
set -euo pipefail

CYCLE="${1:?usage: e2e-installed-scan.sh <ide-cycle-work-dir> <real-cli-work-dir>}"
CLI="${2:?usage: e2e-installed-scan.sh <ide-cycle-work-dir> <real-cli-work-dir>}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Never as root, for the reason verify-in-container.sh gives.
if [ "$(id -u)" = 0 ]; then
  exec bash "$HERE/run-unprivileged.sh" bash "$HERE/e2e-installed-scan.sh" "$@"
fi

say() { printf '== %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

MANIFEST="$CYCLE/installed-plugins.env"
[ -f "$MANIFEST" ] || fail "no $MANIFEST; run e2e-ide-cycle.sh $CYCLE first"
HEAD_VERSION="" HEAD_ZIP="" HEAD_PLUGIN_DIR="" PREV_VERSION="" PREV_ZIP="" PREV_PLUGIN_DIR=""
# shellcheck source=/dev/null
. "$MANIFEST"
for name in HEAD_VERSION HEAD_ZIP HEAD_PLUGIN_DIR PREV_VERSION PREV_ZIP PREV_PLUGIN_DIR; do
  [ -n "${!name}" ] || fail "$MANIFEST sets no $name"
done
BIN="$CLI/venv/bin"
[ -x "$BIN/ashx" ] || [ -x "$BIN/ash" ] || fail "no ASH console scripts under $BIN; run e2e-real-cli.sh $CLI first"

cd "$HERE"
say "provision defusedxml for the test census"
. "$HERE/provision-defusedxml.sh"

# --------------------------------------------------------------------------
# 1. The installs are what the zips hold.
# --------------------------------------------------------------------------
same_as_zip() {
  python3 - "$1" "$2" <<'PY'
import hashlib, pathlib, sys, zipfile
root, zip_path = pathlib.Path(sys.argv[1]), sys.argv[2]
archive = zipfile.ZipFile(zip_path)
top = root.name
expected = {n.split("/", 1)[1]: hashlib.sha256(archive.read(n)).hexdigest()
            for n in archive.namelist() if not n.endswith("/") and n.startswith(top + "/")}
found = {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
         for p in root.rglob("*") if p.is_file()}
if not expected or found != expected:
    sys.exit(f"{root} differs from {zip_path}: found {sorted(found)}, zip has {sorted(expected)}")
print(f"   {root}: {', '.join(sorted(found))} (identical to {pathlib.Path(zip_path).name})")
PY
}
say "the installs still match their zips"
same_as_zip "$HEAD_PLUGIN_DIR" "$HEAD_ZIP"
same_as_zip "$PREV_PLUGIN_DIR" "$PREV_ZIP"

scan_through() {
  ASH_JB_REAL_CLI_BIN="$BIN" ./gradlew --no-daemon --console=plain "$@"
}

# --------------------------------------------------------------------------
# 2. Negative control: N expected, N-1 installed.
# --------------------------------------------------------------------------
say "negative control: the installed-zip scan against N-1 ($PREV_VERSION) while expecting N ($HEAD_VERSION) must fail"
if scan_through installedZipTest \
  -Pash.installed.plugin.dir="$PREV_PLUGIN_DIR" -Pash.installed.plugin.version="$HEAD_VERSION" \
  > "$CYCLE/installed-scan-negative.log" 2>&1; then
  tail -n 30 "$CYCLE/installed-scan-negative.log"
  fail "installedZipTest passed against N-1 while expecting N; it cannot tell which plugin it tested"
fi
if ! grep -q "the loaded plugin&apos;s version\|the loaded plugin's version" build/test-results/installedZipTest/TEST-*.xml; then
  tail -n 30 "$CYCLE/installed-scan-negative.log"
  fail "installedZipTest failed against N-1, but not on the loaded version; see the log above"
fi
grep -q "loaded plugin: .* $PREV_VERSION from " "$CYCLE/installed-scan-negative.log" \
  || fail "the negative run's log does not show N-1 loaded; see $CYCLE/installed-scan-negative.log"
printf '   failed as required: the loaded version was %s, not %s\n' "$PREV_VERSION" "$HEAD_VERSION"

# --------------------------------------------------------------------------
# 3. The scan through N as installed.
# --------------------------------------------------------------------------
say "a real scan through N ($HEAD_VERSION) as installed at $HEAD_PLUGIN_DIR"
scan_through installedZipTest assertInstalledZipTestsRan \
  -Pash.installed.plugin.dir="$HEAD_PLUGIN_DIR" -Pash.installed.plugin.version="$HEAD_VERSION" \
  | tee "$CYCLE/installed-scan.log"
grep -qF "$HEAD_VERSION from $(cd "$HEAD_PLUGIN_DIR" && pwd -P);" "$CYCLE/installed-scan.log" \
  || fail "the log does not show N loaded from $HEAD_PLUGIN_DIR"

echo
echo "JETBRAINS INSTALLED-ZIP SCAN PASSED: findings scan through $HEAD_VERSION as installed, N-1 negative control failed as required"
