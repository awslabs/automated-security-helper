#!/usr/bin/env bash
#
# The Flatpak channel end to end: builds the bundle from this tree's wheel, installs it
# fresh, runs the three e2e cases from tests/e2e/fixtures/cases.json through the
# installed app, upgrades from an N-1 bundle through a local remote, uninstalls, and
# shows each gate failing on a planted wrong outcome.
#
#   DIST       directory holding the head wheel (default: $REPO/dist)
#   PREV_DIST  directory holding the N-1 wheel, the previous commit with a lower
#              version, as packaging/build-test-wheels.sh writes it
#              (default: $REPO/dist-prev)
#   PREV_SRC   that commit's tree, whose packaging/flatpak/build.sh builds the N-1
#              bundle (default: prev/src beside PREV_DIST, where build-test-wheels.sh
#              writes it); N1_ENV, the record of which commit it is (default: n1.env
#              beside PREV_DIST)
#
# Every scan is judged by scripts/e2e/assert_outcome.py, the verdict every e2e channel
# shares: findings exits exactly 2 with 3 detect-secrets findings, clean exits exactly 0,
# and incomplete exits exactly 1 with opengrep MISSING, each with reports/ash.sarif and
# ash_aggregated_results.json at their exact paths. An earlier revision of this script
# captured the findings scan's exit code into SCAN_RC, printed it, and compared it to
# nothing, and it accepted any *.sarif under the output directory. Both are gone.
#
# The scan that has to find something matters more for a Flatpak than for the other
# channels: a sandbox that cannot see the source tree cannot scan it. Step 7 shows that
# happening on purpose, on a path outside the grant, so step 8's findings mean the
# grant works.
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
PREV_ROOT="$(cd "$(dirname "$PREV_DIST")" && pwd)"
PREV_SRC="${PREV_SRC:-$PREV_ROOT/prev/src}"
N1_ENV="${N1_ENV:-$PREV_ROOT/n1.env}"
# Scratch for build output and step logs: one mktemp directory, removed on exit, so a
# run leaves nothing behind in the temp directory and two runs cannot share log names.
# mktemp honors TMPDIR; CI points that at RUNNER_TEMP.
WORK="$(mktemp -d -t ash-flatpak.XXXXXX)"
OUT="${OUT:-$WORK/flatpakbuild}"
APP_ID="io.github.awslabs.automated_security_helper"
RUNTIME_VERSION="24.08"
# The runtime is pinned by OSTree commit, not only by branch. Flathub rebuilds
# org.freedesktop.Sdk//24.08 in place for point releases, so the branch alone lets the
# build and test input change under an unchanged tree. The pin is per architecture
# because each one is its own commit; an architecture without a pin fails rather than
# floating. To refresh, run
#   flatpak remote-info --system flathub org.freedesktop.Sdk//24.08
# and copy its Commit line here (and say why in the commit message). A pin Flathub has
# pruned fails at the `flatpak update --commit` below, loudly, which is the point.
# Measured 2026-10-08: this commit is the branch tip, dated 2026-10-03, and flathub
# reports org.freedesktop.Platform 24.08 end-of-life, so it is also the last one.
RUNTIME_COMMIT_X86_64="f840a6835a5d303866d8309ca512833fb516910f6994662cbe1c298371ef6873"

# shellcheck source=packaging/cli-name.sh
. "$REPO/packaging/cli-name.sh"
: "${ASH_CLI_NAME:?packaging/cli-name.sh did not set ASH_CLI_NAME}"

# The fixture does NOT go in /tmp, and that is not a style choice. --filesystem=host
# grants every toplevel path under / except a reserved set, and /tmp, /var, /root, /boot,
# /efi and /sys are outside it -- an app sees its own tmpfs at /tmp, not the host's. A
# fixture in /tmp would therefore be invisible to the sandboxed scan, the scan would
# report zero findings, and the obvious conclusion would be that the manifest's grant is
# broken. /srv is an ordinary toplevel and is covered.
#
# The negative control in step 7 is the one thing that must be under the literal /tmp,
# since what it proves is that /tmp is hidden. mktemp gives it a unique name and the
# EXIT trap below removes it; TMPDIR cannot be used for it because CI points TMPDIR at
# a directory the sandbox can see.
FIX_UNREACHABLE="$(mktemp -d /tmp/ash-negative-control.XXXXXX)"
trap 'rm -rf "$WORK" "$FIX_UNREACHABLE"' EXIT
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

# `$1` is what the app printed for --version or -V; it must END in v$2, the way the
# CLI prints it ("... v4.0.0"). A substring match would accept 4.0.0 inside 14.0.01.
assert_reports_version() {
  case "$1" in
    *"v$2") ;;
    *)
      echo "   FAIL: the app reports '$1', expected v$2" >&2
      exit 1
      ;;
  esac
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
if ! bwrap --dev-bind / / --unshare-user-try /bin/true 2>"$WORK/bwrap.err"; then
  echo "   FAIL: bwrap cannot create a sandbox here, so flatpak-builder cannot run." >&2
  sed 's/^/         /' "$WORK/bwrap.err" >&2
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
    flathub "org.freedesktop.Sdk//${RUNTIME_VERSION}" >"$WORK/runtime-install.log" 2>&1; then
  echo "   flatpak install of the runtime exited non-zero; its output:"
  sed 's/^/     /' "$WORK/runtime-install.log"
fi
flatpak info --system "org.freedesktop.Sdk//${RUNTIME_VERSION}" >/dev/null || {
  echo "   FAIL: org.freedesktop.Sdk//${RUNTIME_VERSION} is not installed" >&2
  exit 1
}
case "$(uname -m)" in
  x86_64) RUNTIME_COMMIT="$RUNTIME_COMMIT_X86_64" ;;
  *)
    echo "   FAIL: no pinned org.freedesktop.Sdk commit for $(uname -m); add one above" >&2
    exit 1
    ;;
esac
# Deploys exactly that commit whatever the branch now points at, then reads back what
# is installed: the update's exit code alone would not say which commit it left.
flatpak update -y --system --noninteractive --commit="$RUNTIME_COMMIT" \
  "org.freedesktop.Sdk//${RUNTIME_VERSION}" >"$WORK/runtime-pin.log" 2>&1 || {
  echo "   FAIL: could not deploy the pinned runtime commit $RUNTIME_COMMIT" >&2
  sed 's/^/     /' "$WORK/runtime-pin.log" >&2
  exit 1
}
assert_runtime_commit() {
  local installed
  installed="$(flatpak info --system --show-commit "org.freedesktop.Sdk//${RUNTIME_VERSION}")"
  if [ "$installed" != "$1" ]; then
    echo "   FAIL: org.freedesktop.Sdk//${RUNTIME_VERSION} is at commit $installed, not the pinned $1" >&2
    exit 1
  fi
}
assert_runtime_commit "$RUNTIME_COMMIT"
echo "   runtime: org.freedesktop.Sdk//${RUNTIME_VERSION} at the pinned commit $RUNTIME_COMMIT"
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
#
# N-1 is the previous commit (packaging/n1-source.sh), built with THAT commit's
# packaging/flatpak/build.sh, manifest and launcher, so `flatpak update` moves an
# install an older bundle made onto this one. The record says which two commits.
N1_SHA="$(sed -n 's/^N1_SHA=//p' "$N1_ENV" 2>/dev/null || true)"
N1_HEAD="$(sed -n 's/^N1_HEAD=//p' "$N1_ENV" 2>/dev/null || true)"
[ -n "$N1_SHA" ] && [ -n "$N1_HEAD" ] && [ "$N1_SHA" != "$N1_HEAD" ] || {
  echo "   FAIL: $N1_ENV does not record an N-1 commit different from HEAD" >&2
  exit 1
}
[ -x "$PREV_SRC/packaging/flatpak/build.sh" ] || {
  echo "   FAIL: no N-1 packaging/flatpak/build.sh under $PREV_SRC" >&2
  exit 1
}
echo "   N-1: commit $N1_SHA, packaged by its own packaging/flatpak; N: commit $N1_HEAD"
PREV_BUNDLE="$("$PREV_SRC/packaging/flatpak/build.sh" "$PREV_WHEEL" "$OUT/prev")"
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
  echo "   Without it ASH cannot see the tree it is asked to scan, and every scan of" >&2
  echo "   a host path would be refused as a missing source directory." >&2
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
REPORTED="$(flatpak run "$APP_ID" --version)"
echo "   flatpak run \$APP_ID --version -> $REPORTED"
assert_reports_version "$REPORTED" "$VERSION"
REPORTED="$(flatpak run "$APP_ID" -V)"
echo "   -V (the short form the CLI contract fixes as --version) -> $REPORTED"
assert_reports_version "$REPORTED" "$VERSION"
for name in ashv3 automated-security-helper; do
  echo -n "   --command=$name --version -> "
  flatpak run --command="$name" "$APP_ID" --version 2>"$WORK/${name}.err" || {
    echo "   FAIL: $name is not usable" >&2; cat "$WORK/${name}.err" >&2; exit 1
  }
  if [ -s "$WORK/${name}.err" ]; then
    echo "     stderr: $(head -2 "$WORK/${name}.err" | tr '\n' ' ')"
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

echo "== 7. negative control: a fixture the sandbox cannot reach must not be scanned"
# Run BEFORE the real scan. This is the positive control for the whole verification:
# it shows the sandbox really hides a path outside the grant, so the findings in step 8
# are evidence the grant is doing work rather than evidence that the app sees
# everything.
#
# /tmp is deliberately outside --filesystem=host, so the app sees its own empty tmpfs
# there: the fixture directory does not exist inside the sandbox at all. ASH refuses a
# --source-dir that does not exist (cli/scan.py: "Source directory does not exist",
# exit 1), so that refusal, naming this exact path, IS what an unreachable tree looks
# like. An earlier version of this step expected a clean exit-0 scan, counted results
# over any *.sarif it could find, and printed the exit code without comparing it; once
# ASH started refusing a missing source directory it read rc=1 with no report as "0
# findings" and kept passing. Each of the three facts is now required:
#
#   - exit exactly 1, the usage refusal, and not 0, 2 or a crash;
#   - the refusal names this fixture's path, so the exit 1 is that refusal;
#   - neither report exists at its exact path under an output directory the sandbox
#     CAN write (under /srv, inside the grant), so "no report" means the scan stopped
#     before writing one rather than wrote it somewhere the host cannot see.
#
# The file is the findings case's own fixture, copied rather than written out here, so
# the only difference between this scan and that case in step 8 is whether the sandbox
# can reach the tree. It also keeps the planted key out of this script, which therefore
# needs no secret-scanner entry of its own.
cp "$REPO/tests/e2e/fixtures/findings/leak.py" "$FIX_UNREACHABLE/leak.py"
NEG_OUT=/srv/ash-negative-control-out
rm -rf "$NEG_OUT"
set +e
flatpak run "$APP_ID" scan --source-dir "$FIX_UNREACHABLE" \
  --output-dir "$NEG_OUT" \
  --scanners detect-secrets --no-progress >"$WORK/scan-negative.log" 2>&1
NEG_RC=$?
set -e
echo "   /tmp fixture: rc=$NEG_RC"
sed -n 's/^/     /;/Source directory/p' "$WORK/scan-negative.log"
NEG_PROBLEMS=0
if [ "$NEG_RC" -ne 1 ]; then
  echo "   FAIL: the scan of a tree outside the grant exited $NEG_RC, not 1 (refused)" >&2
  NEG_PROBLEMS=1
fi
if ! grep -qF "Source directory does not exist: $FIX_UNREACHABLE" "$WORK/scan-negative.log"; then
  echo "   FAIL: the scan did not refuse $FIX_UNREACHABLE as missing, so the sandbox may see" >&2
  echo "   the host's /tmp and step 8 proves nothing about the grant" >&2
  NEG_PROBLEMS=1
fi
for report in reports/ash.sarif ash_aggregated_results.json; do
  if [ -e "$NEG_OUT/$report" ]; then
    echo "   FAIL: $NEG_OUT/$report exists, so the sandbox scanned a tree it should not see" >&2
    NEG_PROBLEMS=1
  fi
done
if [ "$NEG_PROBLEMS" -ne 0 ]; then
  tail -n 25 "$WORK/scan-negative.log" >&2
  exit 1
fi
rm -rf "$NEG_OUT"
echo "   OK: inside the sandbox the /tmp fixture does not exist: refused with exit 1, no report"

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
flatpak uninstall -y --system --noninteractive "$APP_ID" >"$WORK/uninstall.log" 2>&1 || {
  echo "   FAIL: plain uninstall failed" >&2; cat "$WORK/uninstall.log" >&2; exit 1
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
flatpak install -y --system --noninteractive --bundle "$BUNDLE" >"$WORK/reinstall.log" 2>&1 || {
  echo "   FAIL: reinstalling from the bundle failed" >&2; cat "$WORK/reinstall.log" >&2
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
assert_reports_version "$PREV_REPORTED" "$PREV_VERSION"
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
assert_reports_version "$NEW_REPORTED" "$VERSION"
NEW_VENV="$DATA_ROOT/$(basename "$WHEEL" .whl)-"
ls -d "$NEW_VENV"py3.* >/dev/null 2>&1 || {
  echo "   FAIL: the first run after the update built no venv for the N wheel" >&2
  ls -la "$DATA_ROOT" >&2
  exit 1
}
echo "   venvs after the update (the N-1 one lingers by design; README.flatpak):"
ls -d "$DATA_ROOT"/automated_security_helper-* | sed 's/^/     /'
run_case --cli "$SHIM" --case findings --work "$E2E/scans" --label upgrade-to-n

# `flatpak update APP` may pull runtime updates too; the build input must still be the
# pinned commit after it.
assert_runtime_commit "$RUNTIME_COMMIT"
echo "   runtime still at the pinned commit after the update"

uninstall_delete_data upgrade
flatpak remote-delete --system "$E2E_REMOTE"
echo "   removed the local remote $E2E_REMOTE"

echo
echo "FLATPAK VERIFICATION PASSED"
