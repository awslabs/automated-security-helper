#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Runs the JetBrains plugin's visual snapshot suite: a real IDE on an Xvfb display, driven by
# Remote-Robot, with every scene compared pixel for pixel against the PNGs committed under
# src/uiTest/snapshots/__snapshots__.
#
#   bash editors/jetbrains/ui-test-in-container.sh [runs]
#
# From a checkout, the way CI runs it:
#
#   docker build -t ash-jetbrains-ui editors/jetbrains/ui-test
#   docker run --rm --init -v "$PWD:$PWD" -w "$PWD" ash-jetbrains-ui \
#     bash editors/jetbrains/ui-test-in-container.sh 2
#
# Must run inside the image editors/jetbrains/ui-test/Dockerfile builds, with the repository
# mounted, started with --init. The baselines are pixels of that image, so a run anywhere else
# is not a comparison. `runs` (default 1) starts the IDE that many times in a row, from a fresh
# configuration each time, and requires every run to render identical pixels: that is how the
# suite's determinism is measured, and CI runs it with 2 so a nondeterministic scene fails there
# too rather than only in whoever's run happens to flake.
#
# Set ASH_SNAPSHOT_UPDATE=1 to rewrite the baselines (Gradle's -Psnapshot-update). Gradle refuses
# that flag when CI or GITHUB_ACTIONS is "true", so CI can only compare.
#
# WHAT IS PINNED HERE, as opposed to in the Dockerfile and build.gradle.kts:
#   * the display: one 1920x1080 screen at 24-bit depth and 96 DPI, so the IDE computes a UI
#     scale of exactly 1;
#   * the paths the IDE shows: the project is always /tmp/ash-ui/project and the stub CLI
#     /tmp/ash-ui/bin/ashx, because both appear in rendered text (the notification names the
#     report's path);
#   * the scan's output: the stub replays the captured real exit-1 run in
#     src/test/resources/real-cli/exit1, so the findings and the incomplete-scan notification
#     are ASH's own output and the same every time;
#   * the locale, time zone and environment the IDE inherits.
#
# Nothing is published and nothing leaves the container but files under build/.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

# Never as root, for the reason verify-in-container.sh gives.
if [ "$(id -u)" = 0 ]; then
  exec bash "$HERE/run-unprivileged.sh" bash "$HERE/ui-test-in-container.sh" "$@"
fi

RUNS="${1:-1}"
case "$RUNS" in ''|*[!0-9]*) echo "runs must be a positive integer, got '$RUNS'" >&2; exit 2;; esac
[ "$RUNS" -ge 1 ] || { echo "runs must be at least 1" >&2; exit 2; }

say() { printf '== %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

UPDATE_ARGS=()
if [ "${ASH_SNAPSHOT_UPDATE:-}" = 1 ]; then
  UPDATE_ARGS=(-Psnapshot-update)
  [ "$RUNS" = 1 ] || fail "ASH_SNAPSHOT_UPDATE writes the baselines; run it with runs=1, then compare with more"
fi

export LANG=C.UTF-8 LC_ALL=C.UTF-8 TZ=UTC
export DISPLAY=:99
UI_ROOT=/tmp/ash-ui
export ASH_UI_PROJECT="$UI_ROOT/project"
RESULTS="$HERE/build/ui-snapshots"
LOGS="$HERE/build/ui-logs"
mkdir -p "$LOGS"

say "toolchain"
java -version 2>&1 | head -1 | sed 's/^/   /'
dpkg-query -W -f='   ${Package} ${Version}\n' xvfb fontconfig fonts-dejavu-core 2>/dev/null

say "provision defusedxml for the test-count gate"
# provision-defusedxml.sh carries the reasons and the pinned digest.
. "$HERE/provision-defusedxml.sh"

say "start Xvfb on $DISPLAY: 1920x1080x24, 96 DPI"
Xvfb "$DISPLAY" -screen 0 1920x1080x24 -dpi 96 -nolisten tcp -noreset > "$LOGS/xvfb.log" 2>&1 &
XVFB_PID=$!
IDE_PID=""
cleanup() {
  if [ -n "$IDE_PID" ]; then kill -- "-$IDE_PID" 2>/dev/null || kill "$IDE_PID" 2>/dev/null || true; fi
  kill "$XVFB_PID" 2>/dev/null || true
}
trap cleanup EXIT
for _ in $(seq 1 50); do xdpyinfo -display "$DISPLAY" > /dev/null 2>&1 && break; sleep 0.2; done
xdpyinfo -display "$DISPLAY" | grep -E 'dimensions|resolution|depth of root' | sed 's/^ */   /'

say "compile the plugin, the sandbox and the visual suite before the IDE starts"
./gradlew --no-daemon --console=plain -q uiTestClasses prepareSandbox_runIdeForUiTests

# A fixed project with the planted secret, and a stub ASH CLI that replays the captured real
# exit-1 run: three detect-secrets findings and cfn-nag MISSING.
fresh_project() {
  rm -rf "$UI_ROOT"
  mkdir -p "$ASH_UI_PROJECT" "$UI_ROOT/bin"
  # The project's own settings (an inspection profile with the spell checker off, so the only
  # underlines in the editor are ASH's), then the planted-secret fixture.
  cp -R src/uiTest/project/. "$ASH_UI_PROJECT/"
  cp src/test/resources/fixtures/leak.py "$ASH_UI_PROJECT/leak.py"
  local capture="$HERE/src/test/resources/real-cli/exit1"
  cat > "$UI_ROOT/bin/ashx" <<SH
#!/bin/sh
if [ "\$1" = --version ]; then echo 'awslabs/automated-security-helper v3.7.0'; exit 0; fi
out=''
while [ \$# -gt 0 ]; do case "\$1" in --output-dir) out="\$2"; shift 2;; *) shift;; esac; done
mkdir -p "\$out/reports"
cp '$capture/ash.sarif' "\$out/reports/ash.sarif"
cp '$capture/ash_aggregated_results.json' "\$out/ash_aggregated_results.json"
cat '$capture/console-tail.txt' >&2
exit 1
SH
  chmod 755 "$UI_ROOT/bin/ashx"
}

wait_for_robot() {
  local deadline=$((SECONDS + 600))
  until curl -sf -o /dev/null "http://127.0.0.1:8082/hierarchy"; do
    kill -0 "$IDE_PID" 2>/dev/null || { tail -n 40 "$1" >&2; fail "the IDE exited before the robot server answered"; }
    [ "$SECONDS" -lt "$deadline" ] || { tail -n 40 "$1" >&2; fail "the robot server did not answer within 600s"; }
    sleep 2
  done
}

declare -a DIGESTS=()
for run in $(seq 1 "$RUNS"); do
  say "run $run of $RUNS: fresh project, fresh IDE configuration, IDE start"
  fresh_project
  # runIdeForUiTests removes the previous start's configuration, caches, indexes and logs
  # before every start (see build.gradle.kts), so each run starts the same way.
  IDE_LOG="$LOGS/ide-run$run.log"
  setsid ./gradlew --no-daemon --console=plain runIdeForUiTests > "$IDE_LOG" 2>&1 &
  IDE_PID=$!
  wait_for_robot "$IDE_LOG"
  say "run $run: the robot server answers; rendering the scenes"
  rm -rf "$RESULTS"
  ./gradlew --no-daemon --console=plain uiTest assertUiTestsRan assertUiSnapshotsUsed "${UPDATE_ARGS[@]}"
  DIGESTS+=("$(cd "$RESULTS" && sha256sum rendered/*.rgba | sha256sum | cut -c1-64)")
  say "run $run: rendered-pixel digest ${DIGESTS[-1]}"
  (cd "$RESULTS" && sha256sum rendered/*.rgba) | sed 's/^/   /'
  kill -- "-$IDE_PID" 2>/dev/null || true
  wait "$IDE_PID" 2>/dev/null || true
  IDE_PID=""
done

if [ "$RUNS" -gt 1 ]; then
  for digest in "${DIGESTS[@]}"; do
    [ "$digest" = "${DIGESTS[0]}" ] || fail "the $RUNS runs rendered different pixels: ${DIGESTS[*]}"
  done
  say "all $RUNS runs rendered identical pixels (${DIGESTS[0]})"
fi

echo
echo "JETBRAINS VISUAL SNAPSHOTS PASSED ($RUNS run(s))"
