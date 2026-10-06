#!/usr/bin/env bash
#
# The Flatpak channel end to end: builds the bundle from this tree's wheel, installs it
# fresh, runs the three e2e cases from tests/e2e/fixtures/cases.json through the
# installed app, upgrades from an N-1 bundle through a local remote, uninstalls, and
# shows each gate failing on a planted wrong outcome.
#
#   DIST       directory holding the head wheel (default: $REPO/dist)
#   PREV_DIST  directory holding the N-1 wheel, the same tree with a lower version, as
#              packaging/build-test-wheels.sh writes it (default: $REPO/dist-prev)
#
# Every scan is judged by scripts/e2e/assert_outcome.py, the verdict every e2e channel
# shares: findings exits exactly 2 with 3 detect-secrets findings, clean exits exactly 0,
# and incomplete exits exactly 1 with opengrep MISSING, each with reports/ash.sarif and
# ash_aggregated_results.json at their exact paths. An earlier revision of this script
# captured the findings scan's exit code into SCAN_RC, printed it, and compared it to
# nothing, and it accepted any *.sarif under the output directory. Both are gone.
#
# The scan that has to find something matters more for a Flatpak than for the other
# channels: a sandbox that cannot see the source tree produces exactly a clean,
# zero-finding, exit-0 scan. Step 7 turns that into a positive control instead of a trap.
#
# WHERE THIS CAN RUN, WHICH IS NOT THE SAME AS THE .deb AND .rpm SCRIPTS
#
# flatpak-builder drives bwrap, and bwrap has to create a user namespace. Measured on a
# Docker 25.0 host:
#
#   docker run fedora:41              bwrap: No permissions to creating new namespace,
#                                     likely because the kernel does not allow
#                                     non-privileged user namespaces.   (exit 1)
#   docker run --privileged fedora:41 exit 0
#
# So unlike packaging/deb/verify-in-container.sh and packaging/rpm/verify-in-container.sh,
# which run in an ordinary job container, this one needs either a privileged container or
# a host that permits unprivileged user namespaces. In CI it runs directly on the
# ubuntu-latest runner for that reason. Locally:
#
#   docker run --rm --privileged -v "$PWD:/src" -v ash-flatpak-store:/var/lib/flatpak \
#     ubuntu:24.04 bash -c 'REPO=/src bash /src/packaging/build-test-wheels.sh /work &&
#       DIST=/work/dist PREV_DIST=/work/dist-prev bash /src/packaging/flatpak/verify-in-container.sh'
#
# ubuntu:24.04 because the CI job runs on ubuntu-latest, so the flatpak and
# flatpak-builder versions match. The dnf branch below still works on Fedora.
#
# The named volume is worth using: the two runtimes are about 2.4 GB and reinstalling
# them on every run dwarfs the rest of the script.
set -euo pipefail

REPO="${REPO:-/src}"
DIST="${DIST:-$REPO/dist}"
PREV_DIST="${PREV_DIST:-$REPO/dist-prev}"
OUT="${OUT:-/tmp/flatpakbuild}"
APP_ID="io.github.awslabs.automated_security_helper"
RUNTIME_VERSION="24.08"

# shellcheck source=packaging/cli-name.sh
. "$REPO/packaging/cli-name.sh"
: "${ASH_CLI_NAME:?packaging/cli-name.sh did not set ASH_CLI_NAME}"

# The fixture does NOT go in /tmp, and that is not a style choice. --filesystem=host
# grants every toplevel path under / except a reserved set, and /tmp, /var, /root, /boot,
# /efi and /sys are outside it -- an app sees its own tmpfs at /tmp, not the host's. A
# fixture in /tmp would therefore be invisible to the sandboxed scan, the scan would
# report zero findings, and the obvious conclusion would be that the manifest's grant is
# broken. /srv is an ordinary toplevel and is covered.
FIX_UNREACHABLE=/tmp/ash-fixture-negative-control
# Everything the e2e cases write: the fixture copies, their output directories, the
# launcher shim run_case.py is pointed at, and the local OSTree repo the upgrade leg
# serves from. Under /srv for the reason above.
E2E=/srv/ash-e2e
E2E_REMOTE=ash-e2e-local

# The harness. Both scripts are standard library only and run under the host's python3;
# neither is installed into, or depends on, the app under test.
run_case() { python3 "$REPO/scripts/e2e/run_case.py" "$@"; }
assert_outcome() { python3 "$REPO/scripts/e2e/assert_outcome.py" "$@"; }

# The version a bundle carries, read from its wheel's filename as build.sh does.
wheel_version() {
  basename "$1" | sed -n 's/^automated_security_helper-\([^-]*\)-py3-none-any\.whl$/\1/p'
}

# Exactly one wheel in a directory, or fail naming the directory.
one_wheel() {
  local dir="$1" found=() w
  for w in "$dir"/*.whl; do
    [ -f "$w" ] && found+=("$w")
  done
  if [ "${#found[@]}" -ne 1 ]; then
    echo "   FAIL: expected exactly 1 wheel in $dir, found ${#found[@]}" >&2
    exit 1
  fi
  printf '%s\n' "${found[0]}"
}

# Uninstalls the app with --delete-data and requires both effects: the ref is gone and
# its data directory is gone.
#
# The exit code is deliberately NOT the assertion here, and the reason is measured rather
# than assumed: in a headless environment --delete-data removes the data and then exits 1
# with "Cannot autolaunch D-Bus without X11 $DISPLAY", because it also tries to revoke the
# app's portal permissions over the session bus. Asserting rc=0 would fail this step on
# every container while the thing it is checking worked, and asserting nothing would let a
# real failure through. So the assertion is on the observable effects, with the exit code
# reported.
uninstall_delete_data() {
  local log="$E2E/delete-data-$1.log" rc
  set +e
  flatpak uninstall -y --system --noninteractive --delete-data "$APP_ID" >"$log" 2>&1
  rc=$?
  set -e
  if [ -d "$DATA_ROOT" ]; then
    echo "   FAIL: $DATA_ROOT survived --delete-data (rc=$rc)" >&2
    cat "$log" >&2
    exit 1
  fi
  if flatpak info --system "$APP_ID" >/dev/null 2>&1; then
    echo "   FAIL: $APP_ID is still installed after uninstall --delete-data (rc=$rc)" >&2
    cat "$log" >&2
    exit 1
  fi
  echo "   OK: --delete-data removed the app and the venvs its runs created (rc=$rc)"
  if [ "$rc" -ne 0 ]; then
    echo "      non-zero exit, and the app and data are gone. Reported rather than hidden:"
    sed 's/^/        /' "$log"
  fi
}

echo "== 1. install build prerequisites"
if command -v dnf >/dev/null; then
  dnf -q -y install flatpak flatpak-builder findutils python3 ostree >/dev/null 2>&1
elif command -v apt-get >/dev/null; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get -qq update >/dev/null
  apt-get -qq install -y --no-install-recommends \
    flatpak flatpak-builder ca-certificates python3 dbus ostree >/dev/null
  # Ubuntu 24.04's flatpak 1.14 refuses `flatpak run` with no system bus. Measured in
  # a privileged ubuntu:24.04 container, which has none:
  #   flatpak run --command=python3 org.freedesktop.Sdk//24.08 -V
  #     -> error: Could not connect: No such file or directory          (exit 1)
  # and the same command prints the runtime's python once a system dbus-daemon is
  # running. A runner host already has one, so this only starts a bus where none exists.
  if [ ! -S /run/dbus/system_bus_socket ]; then
    mkdir -p /run/dbus
    dbus-daemon --system --fork
    echo "   started a system D-Bus (none was running)"
  fi
else
  echo "   FAIL: no dnf and no apt-get; cannot install flatpak-builder" >&2
  exit 1
fi
echo "   $(flatpak --version)"
echo "   $(flatpak-builder --version)"

# Fail here with a message about namespaces rather than 200 lines into a
# flatpak-builder log. This is the check that distinguishes "the manifest is wrong" from
# "this environment cannot build a Flatpak at all".
if ! bwrap --dev-bind / / --unshare-user-try /bin/true 2>/tmp/bwrap.err; then
  echo "   FAIL: bwrap cannot create a sandbox here, so flatpak-builder cannot run." >&2
  sed 's/^/         /' /tmp/bwrap.err >&2
  echo "         Run this in a privileged container, or on a host that permits" >&2
  echo "         unprivileged user namespaces. See the header of this script." >&2
  exit 1
fi
echo "   bwrap can create a sandbox"

flatpak remote-add --if-not-exists --system \
  flathub https://dl.flathub.org/repo/flathub.flatpakrepo
# Sdk is both the runtime and the sdk for this app; see the manifest for why Platform is
# not used. Installing it explicitly rather than letting flatpak-builder do it with
# --install-deps-from keeps the download in a step that says what it is doing.
# Its exit code is not trusted alone: an already-installed runtime makes it report and
# move on, and the `flatpak info` below is the check that the runtime is really there.
if ! flatpak install -y --system --noninteractive \
    flathub "org.freedesktop.Sdk//${RUNTIME_VERSION}" >/tmp/runtime-install.log 2>&1; then
  echo "   flatpak install of the runtime exited non-zero; its output:"
  sed 's/^/     /' /tmp/runtime-install.log
fi
flatpak info --system "org.freedesktop.Sdk//${RUNTIME_VERSION}" >/dev/null || {
  echo "   FAIL: org.freedesktop.Sdk//${RUNTIME_VERSION} is not installed" >&2
  exit 1
}
echo "   runtime: org.freedesktop.Sdk//${RUNTIME_VERSION}"
echo -n "   runtime python: "
flatpak run --command=python3 "org.freedesktop.Sdk//${RUNTIME_VERSION}" -V

echo "== 2. build the N and N-1 bundles"
WHEEL="$(one_wheel "$DIST")"
PREV_WHEEL="$(one_wheel "$PREV_DIST")"
VERSION="$(wheel_version "$WHEEL")"
PREV_VERSION="$(wheel_version "$PREV_WHEEL")"
[ -n "$VERSION" ] && [ -n "$PREV_VERSION" ] || {
  echo "   FAIL: cannot read a version from $(basename "$WHEEL") or $(basename "$PREV_WHEEL")" >&2
  exit 1
}
# The upgrade in step 12 must cross a real version change, or `flatpak update` and the
# launcher's per-wheel venv path would both be exercised on a no-op.
[ "$VERSION" != "$PREV_VERSION" ] || {
  echo "   FAIL: the N and N-1 wheels are both $VERSION" >&2
  exit 1
}
[ "$(printf '%s\n%s\n' "$PREV_VERSION" "$VERSION" | sort -V | tail -n 1)" = "$VERSION" ] || {
  echo "   FAIL: N-1 ($PREV_VERSION) does not sort below N ($VERSION)" >&2
  exit 1
}
echo "   wheel N:   $(basename "$WHEEL")"
echo "   wheel N-1: $(basename "$PREV_WHEEL")"
# N-1 first. `flatpak update` refuses a commit whose timestamp is older than the
# installed one, measured: with N built first, step 12's update failed with "Update is
# older than current version". Building in release order keeps the timestamps in the
# order a real release would produce them.
PREV_BUNDLE="$("$REPO/packaging/flatpak/build.sh" "$PREV_WHEEL" "$OUT/prev")"
echo "   built N-1: $PREV_BUNDLE ($(du -h "$PREV_BUNDLE" | cut -f1))"
BUNDLE="$("$REPO/packaging/flatpak/build.sh" "$WHEEL" "$OUT")"
echo "   built N:   $BUNDLE ($(du -h "$BUNDLE" | cut -f1))"

echo "== 3. install it, fresh"
# Fresh means nothing of this app is on the host before the install: no installed ref
# and no data directory left by an earlier run.
if flatpak info --system "$APP_ID" >/dev/null 2>&1; then
  echo "   FAIL: $APP_ID is already installed, so this would not be a fresh install" >&2
  exit 1
fi
DATA_ROOT="$HOME/.var/app/$APP_ID/data"
if [ -e "$HOME/.var/app/$APP_ID" ]; then
  echo "   FAIL: $HOME/.var/app/$APP_ID exists from an earlier run" >&2
  exit 1
fi
flatpak install -y --system --noninteractive --bundle "$BUNDLE" >/dev/null 2>&1
flatpak info --system "$APP_ID" | sed -n '1,8p;/Runtime:/p'

echo "== 4. package metadata is well formed"
# `flatpak info --show-metadata` reads the metadata out of the INSTALLED app, so unlike
# build.sh's check on the build directory this one is a property of the artifact that
# was written, bundled, and read back.
META="$(flatpak info --system --show-metadata "$APP_ID")"
printf '%s\n' "$META" | sed 's/^/   /'
printf '%s\n' "$META" | grep -Eq '^filesystems=(.*;)?host(;|$)' || {
  echo "   FAIL: the installed app does not have filesystems=host." >&2
  echo "   Without it ASH cannot read the tree it is asked to scan; step 7 would" >&2
  echo "   report zero findings and exit 0, which is the silent pass this package" >&2
  echo "   must not ship." >&2
  exit 1
}
printf '%s\n' "$META" | grep -Eq '^shared=(.*;)?network(;|$)' || {
  echo "   FAIL: the installed app does not have shared=network, so its first-run" >&2
  echo "   dependency resolution can never succeed." >&2
  exit 1
}

# The payload must be ASH's wheel and nothing else. This is the invariant check at the
# package layer: the contents gate covers the wheel, this covers what the Flatpak adds.
# Counted by asking the installed app to list its own payload directory, so a bundle
# that gained a wheel between build.sh's check and installation is still caught.
PAYLOAD_WHEELS="$(flatpak run --command=sh "$APP_ID" -c \
  'ls /app/share/ash/wheels/*.whl 2>/dev/null | wc -l' | tr -d '[:space:]')"
echo "   wheels in package: $PAYLOAD_WHEELS"
[ "$PAYLOAD_WHEELS" -eq 1 ] || {
  echo "   FAIL: expected exactly 1 bundled wheel, found $PAYLOAD_WHEELS." >&2
  echo "   Bundling dependency wheels would put detect-secrets, a scanner, in a" >&2
  echo "   published artifact. See packaging/README.md." >&2
  exit 1
}
# A wheel count alone would miss `pip install --target /app`, which leaves unpacked
# modules and .dist-info directories and no .whl at all.
STRAY="$(flatpak run --command=sh "$APP_ID" -c \
  'find /app -maxdepth 5 -name "*.dist-info" -o -maxdepth 5 -name "*.egg-info" 2>/dev/null | head -5')"
[ -z "$STRAY" ] || {
  echo "   FAIL: the app carries installed Python distributions:" >&2
  printf '     %s\n' $STRAY >&2
  exit 1
}
echo "   no installed Python distributions under /app"

echo "== 5. all three entry points work"
# The entry-point contract: ashx is canonical (the app's `command`), ashv3 is
# deprecated and warns once on stderr, automated-security-helper is kept indefinitely
# and is silent. All three come from the wheel's [project.scripts], so a package that
# installed a subset would drop the escape-hatch name on exactly the hosts it exists
# for. The wheel's deprecated `ash` script is deliberately not exposed (that alias is
# kept only for pip, Homebrew and the container image), and that is asserted too.
#
# This is also where the first run happens: the launcher builds the venv and pip-installs
# the wheel, which needs the network grant asserted in step 4.
echo -n "   flatpak run \$APP_ID --version -> "
flatpak run "$APP_ID" --version
echo -n "   -V (the short form the CLI contract fixes as --version) -> "
flatpak run "$APP_ID" -V
for name in ashv3 automated-security-helper; do
  echo -n "   --command=$name --version -> "
  flatpak run --command="$name" "$APP_ID" --version 2>/tmp/${name}.err || {
    echo "   FAIL: $name is not usable" >&2; cat /tmp/${name}.err >&2; exit 1
  }
  if [ -s "/tmp/${name}.err" ]; then
    echo "     stderr: $(head -2 /tmp/${name}.err | tr '\n' ' ')"
  fi
done
# Read from the installed app, so a bundle that gained /app/bin/ash after build.sh's
# check is still caught. `ls` rather than `test -e` so the listing is in the log.
APP_BIN="$(flatpak run --command=ls "$APP_ID" /app/bin)"
echo "   /app/bin: $(printf '%s\n' "$APP_BIN" | tr '\n' ' ')"
if printf '%s\n' "$APP_BIN" | grep -qx 'ash'; then
  echo "   FAIL: the app exports /app/bin/ash. The Flatpak exposes ashx; the deprecated" >&2
  echo "   ash alias is kept only for pip, Homebrew and the container image." >&2
  exit 1
fi
printf '%s\n' "$APP_BIN" | grep -qx 'ashx' || {
  echo "   FAIL: /app/bin/ashx is missing from the installed app." >&2
  exit 1
}

echo "== 6. the venv was built in the app's own data directory, not in /app"
# /app is a read-only OSTree checkout, so this is the property that makes the first-run
# bootstrap possible at all -- and the reason removal behaves differently from the .deb
# and .rpm (step 9).
DATA_ROOT="$HOME/.var/app/$APP_ID/data"
ls -d "$DATA_ROOT"/automated_security_helper-*-py3.* 2>/dev/null | sed 's/^/   /' || {
  echo "   FAIL: no venv under $DATA_ROOT" >&2
  ls -la "$DATA_ROOT" 2>&1 | sed 's/^/     /' >&2 || true
  exit 1
}
echo -n "   ashx resolved inside the sandbox: "
flatpak run --command=sh "$APP_ID" -c 'command -v ashx; readlink -f "$XDG_DATA_HOME" 2>/dev/null | head -1'

echo "== 7. negative control: a fixture the sandbox cannot reach must find nothing"
# Run BEFORE the real scan. This is the positive control for the whole verification:
# it proves that a zero-finding result is what an unreachable source tree looks like, so
# the non-zero result in step 8 is evidence the grant is doing work rather than evidence
# that detect-secrets fires on anything.
#
# /tmp is deliberately outside --filesystem=host, so the app sees its own empty tmpfs
# there and the planted secret is not in it.
#
# The file is the findings case's own fixture, copied rather than written out here, so
# the only difference between this scan and that case in step 8 is whether the sandbox
# can reach the tree. It also keeps the planted key out of this script, which therefore
# needs no secret-scanner entry of its own.
rm -rf "$FIX_UNREACHABLE"; mkdir -p "$FIX_UNREACHABLE"
cp "$REPO/tests/e2e/fixtures/findings/leak.py" "$FIX_UNREACHABLE/leak.py"
set +e
flatpak run "$APP_ID" scan --source-dir "$FIX_UNREACHABLE" \
  --output-dir "$FIX_UNREACHABLE/.ash/ash_output" \
  --scanners detect-secrets --no-progress >/tmp/scan-negative.log 2>&1
NEG_RC=$?
set -e
NEG_RESULTS="$(python3 - "$FIX_UNREACHABLE" <<'PY'
import json, pathlib, sys
out = pathlib.Path(sys.argv[1]) / ".ash" / "ash_output"
n = 0
for s in sorted(out.rglob("*.sarif")):
    doc = json.loads(s.read_text(encoding="utf-8"))
    n += sum(len(r.get("results", [])) for r in doc.get("runs", []))
print(n)
PY
)"
echo "   /tmp fixture: rc=$NEG_RC, findings=$NEG_RESULTS"
[ "$NEG_RESULTS" -eq 0 ] || {
  echo "   FAIL: the negative control found $NEG_RESULTS finding(s), so /tmp IS" >&2
  echo "   reachable from the sandbox and step 8 proves nothing about the grant." >&2
  exit 1
}
echo "   OK: an unreachable tree yields a clean, zero-finding, exit-0 scan --"
echo "       which is precisely the failure this package must not ship silently"

echo "== 8. the three e2e cases, through the installed app"
# run_case.py takes an executable, so the app is reached through a two-line shim named
# after the CLI. The shim adds nothing: it is `flatpak run $APP_ID "$@"`, which is the
# command README.flatpak gives users.
rm -rf "$E2E"; mkdir -p "$E2E/bin"
SHIM="$E2E/bin/$ASH_CLI_NAME"
printf '#!/bin/sh\nexec flatpak run %s "$@"\n' "$APP_ID" > "$SHIM"
chmod 0755 "$SHIM"

# The incomplete case depends on two environment variables reaching ASH inside the
# sandbox, one of them set to an EMPTY string. flatpak run passes the caller's
# environment through apart from a fixed set it resets, so this is checked rather than
# assumed: if either were dropped, opengrep could still end MISSING for a different
# reason and the case would pass without testing its trigger.
SEEN="$(ASH_OFFLINE=YES OPENGREP_RULES_CACHE_DIR='' flatpak run --command=sh "$APP_ID" -c \
  'printf "%s|%s" "${ASH_OFFLINE-unset}" "${OPENGREP_RULES_CACHE_DIR-unset}"')"
echo "   case env inside the sandbox: ASH_OFFLINE|OPENGREP_RULES_CACHE_DIR = $SEEN"
[ "$SEEN" = "YES|" ] || {
  echo "   FAIL: the incomplete case's environment does not reach the sandbox as set" >&2
  exit 1
}

for case_name in findings clean incomplete; do
  run_case --cli "$SHIM" --case "$case_name" --work "$E2E/scans"
done

echo "== 9. the default output directory lands inside the scanned tree, on the host"
# --output-dir is NOT passed here, unlike in the cases above. ASH defaults it to
# <source-dir>/.ash/ash_output, which is inside the tree being scanned and therefore on
# the host. Letting it default is the part of the sandbox trade that a passed
# --output-dir would hide. The outcome is judged as the findings case.
FIX="$E2E/default-output"
mkdir -p "$FIX"
cp -R "$REPO/tests/e2e/fixtures/findings/." "$FIX/"
cd "$FIX"
set +e
flatpak run "$APP_ID" scan --source-dir "$FIX" \
  --scanners detect-secrets --no-progress >"$E2E/default-output.log" 2>&1
DEFAULT_RC=$?
set -e
cd /
echo "   scan rc=$DEFAULT_RC"
assert_outcome --case findings --output-dir "$FIX/.ash/ash_output" --rc "$DEFAULT_RC" || {
  tail -25 "$E2E/default-output.log" >&2
  exit 1
}

echo "== 9b. negative controls: each gate must reject a wrong outcome"
# Without these, a green step 8 could mean the verdict cannot fail. Each must be SEEN
# failing, on a real output from this run.
#
# (a) The real clean output judged as a findings outcome: wrong exit code, no findings.
set +e
assert_outcome --case findings --output-dir "$E2E/scans/clean/out" --rc 0 >"$E2E/neg-a.log" 2>&1
NEG_A=$?
set -e
sed 's/^/     /' "$E2E/neg-a.log"
[ "$NEG_A" -eq 1 ] || {
  echo "   FAIL: the clean output passed as a findings outcome (rc=$NEG_A)" >&2
  exit 1
}
echo "   OK: the clean output is rejected as a findings outcome"
# (b) The findings case scanned with --no-fail-on-findings. The scan finds the same
# secret and exits 0, so the exit-code check must fail it. A channel wrapper that
# swallowed the exit code would look exactly like this.
set +e
run_case --cli "$SHIM" --case findings --work "$E2E/scans" --label neg-no-fail -- \
  --no-fail-on-findings >"$E2E/neg-b.log" 2>&1
NEG_B=$?
set -e
sed 's/^/     /' "$E2E/neg-b.log"
[ "$NEG_B" -eq 1 ] || {
  echo "   FAIL: a findings scan that exited 0 was accepted (run_case rc=$NEG_B)" >&2
  exit 1
}
grep -Eq '^::error::\[neg-no-fail\] exit code 0 ' "$E2E/neg-b.log" || {
  echo "   FAIL: the --no-fail-on-findings run failed, but not on its exit code" >&2
  exit 1
}
echo "   OK: a findings scan that exits 0 is rejected on its exit code"

echo "== 10. the container runner is NOT reachable from inside the sandbox"
# Asserted rather than assumed, because README.flatpak tells users this and a document
# that says "does not work" needs the same evidence as one that says "works".
#
# _OCI_RUNNER_CANDIDATES is finch, docker, nerdctl, podman
# (interactions/run_ash_container.py:48), resolved against PATH. The sandbox PATH is
# /app/bin:/usr/bin and /usr is the RUNTIME's /usr -- it is a reserved path that even
# --filesystem=host does not expose -- so a host-installed runner is not on it.
RUNNERS_FOUND="$(flatpak run --command=sh "$APP_ID" -c \
  'for r in finch docker nerdctl podman; do command -v $r; done 2>/dev/null | wc -l' \
  | tr -d '[:space:]')"
echo "   OCI runners visible inside the sandbox: $RUNNERS_FOUND"
[ "$RUNNERS_FOUND" -eq 0 ] || {
  echo "   NOTE: a runner IS visible, so README.flatpak's claim that container mode" >&2
  echo "   cannot work is now wrong and must be corrected." >&2
  exit 1
}
echo -n "   PATH inside the sandbox: "
flatpak run --command=sh "$APP_ID" -c 'echo $PATH'

echo "== 11. a plain uninstall leaves the venv, and --delete-data removes it"
# This is where the Flatpak genuinely differs from the .deb and .rpm, whose removal steps
# assert the venv is gone. Flatpak keeps ~/.var/app/$FLATPAK_ID across an uninstall by
# design -- it is user data, not package content -- so the honest analogue of "removal
# drops the venv" is `--delete-data`. Both halves are measured rather than one assumed.
flatpak uninstall -y --system --noninteractive "$APP_ID" >/tmp/uninstall.log 2>&1 || {
  echo "   FAIL: plain uninstall failed" >&2; cat /tmp/uninstall.log >&2; exit 1
}
if flatpak info --system "$APP_ID" >/dev/null 2>&1; then
  echo "   FAIL: $APP_ID is still installed after a plain uninstall" >&2
  exit 1
fi
echo "   OK: $APP_ID is no longer installed"
if [ ! -d "$DATA_ROOT" ]; then
  echo "   FAIL: a plain uninstall deleted $DATA_ROOT. That contradicts what" >&2
  echo "   README.flatpak tells users about reclaiming the space, so the doc is now" >&2
  echo "   wrong." >&2
  exit 1
fi
echo "   OK: plain uninstall kept $DATA_ROOT ($(du -sh "$DATA_ROOT" | cut -f1))"

# Reinstalled because --delete-data only works on an INSTALLED app. Measured: running it
# against an app that has already been uninstalled exits 1 with "No installed refs found"
# and leaves the data in place. That is why README.flatpak gives --delete-data as the
# uninstall command rather than as a follow-up to one.
flatpak install -y --system --noninteractive --bundle "$BUNDLE" >/tmp/reinstall.log 2>&1 || {
  echo "   FAIL: reinstalling from the bundle failed" >&2; cat /tmp/reinstall.log >&2
  exit 1
}

uninstall_delete_data plain-and-delete

echo "== 12. upgrade: install N-1 from a local remote, then flatpak update to N"
# A user who installed from a remote upgrades with `flatpak update`, so that is the
# path tested, not a bundle reinstall. Both bundles are imported into one local OSTree
# repo served as a system remote. Unsigned, which is why the remote is added with
# --no-gpg-verify: it is a directory on this machine that nothing else can reach, and it
# is deleted at the end of this step.
#
# What the upgrade has to show:
#   - the installed commit changed, and `ashx --version` moved from N-1 to N;
#   - the launcher built a NEW venv for the N wheel instead of serving the N-1 one. The
#     venv path carries the wheel name (see ash-launcher.sh), so an upgrade that kept
#     using the old venv would still report N-1 here;
#   - a findings scan through the upgraded app still exits 2 with its 3 findings.
LREPO="$E2E/repo"
rm -rf "$LREPO"
# build-import-bundle needs an existing repo: measured, on a missing path it fails with
# "'<path>' is not a valid repository". ostree is installed in step 1 for this line.
ostree init --repo="$LREPO" --mode=archive-z2
# build-import-bundle prints GLib-CRITICAL lines about a NULL remote name on flatpak
# 1.14 and exits 0: a bundle built without --repo-url names no origin. Its output is
# kept in a log and shown only if it fails.
import_bundle() {
  flatpak build-import-bundle "$LREPO" "$1" >"$E2E/import-$2.log" 2>&1 || {
    echo "   FAIL: build-import-bundle of $1 failed" >&2
    cat "$E2E/import-$2.log" >&2
    exit 1
  }
  flatpak build-update-repo "$LREPO" >/dev/null
}
import_bundle "$PREV_BUNDLE" prev
if flatpak remotes --system --columns=name | grep -qx "$E2E_REMOTE"; then
  echo "   FAIL: a remote named $E2E_REMOTE already exists; this host is not fresh" >&2
  exit 1
fi
flatpak remote-add --system --no-gpg-verify "$E2E_REMOTE" "file://$LREPO"
flatpak install -y --system --noninteractive "$E2E_REMOTE" "$APP_ID" >"$E2E/install-prev.log" 2>&1 || {
  echo "   FAIL: installing N-1 from the local remote failed" >&2
  cat "$E2E/install-prev.log" >&2
  exit 1
}
PREV_COMMIT="$(flatpak info --system --show-commit "$APP_ID")"
PREV_REPORTED="$(flatpak run "$APP_ID" --version 2>&1)"
echo "   N-1 installed: commit ${PREV_COMMIT:0:12}, reports: $PREV_REPORTED"
case "$PREV_REPORTED" in
  *"$PREV_VERSION"*) ;;
  *) echo "   FAIL: N-1 does not report $PREV_VERSION" >&2; exit 1 ;;
esac
run_case --cli "$SHIM" --case findings --work "$E2E/scans" --label upgrade-from-n-1
PREV_VENV="$DATA_ROOT/$(basename "$PREV_WHEEL" .whl)-"
ls -d "$PREV_VENV"py3.* >/dev/null 2>&1 || {
  echo "   FAIL: N-1's first run built no venv at ${PREV_VENV}py3.*" >&2
  exit 1
}

import_bundle "$BUNDLE" head
flatpak update -y --system --noninteractive "$APP_ID" >"$E2E/update.log" 2>&1 || {
  echo "   FAIL: flatpak update to N failed" >&2
  cat "$E2E/update.log" >&2
  exit 1
}
NEW_COMMIT="$(flatpak info --system --show-commit "$APP_ID")"
[ "$NEW_COMMIT" != "$PREV_COMMIT" ] || {
  echo "   FAIL: flatpak update left the installed commit at ${PREV_COMMIT:0:12}" >&2
  cat "$E2E/update.log" >&2
  exit 1
}
NEW_REPORTED="$(flatpak run "$APP_ID" --version 2>&1)"
echo "   updated to N: commit ${NEW_COMMIT:0:12}, reports: $NEW_REPORTED"
case "$NEW_REPORTED" in
  *"$VERSION"*) ;;
  *) echo "   FAIL: after the update the app does not report $VERSION" >&2; exit 1 ;;
esac
NEW_VENV="$DATA_ROOT/$(basename "$WHEEL" .whl)-"
ls -d "$NEW_VENV"py3.* >/dev/null 2>&1 || {
  echo "   FAIL: the first run after the update built no venv for the N wheel" >&2
  ls -la "$DATA_ROOT" >&2
  exit 1
}
echo "   venvs after the update (the N-1 one lingers by design; README.flatpak):"
ls -d "$DATA_ROOT"/automated_security_helper-* | sed 's/^/     /'
run_case --cli "$SHIM" --case findings --work "$E2E/scans" --label upgrade-to-n

uninstall_delete_data upgrade
flatpak remote-delete --system "$E2E_REMOTE"
echo "   removed the local remote $E2E_REMOTE"

echo
echo "FLATPAK VERIFICATION PASSED"
