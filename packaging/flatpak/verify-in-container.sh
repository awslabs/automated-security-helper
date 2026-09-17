#!/usr/bin/env bash
#
# Builds the Flatpak bundle, installs it, and runs a real scan -- the plan's
# requirement that a package be exercised rather than syntax-checked.
#
# The scan must report a finding. A scan that exits 0 having found nothing is
# indistinguishable from a scan that never ran, which is the failure this whole
# branch's exit-code work exists to remove -- so asserting exit 0 alone would repeat the
# bug in the test. For a Flatpak that is not a hypothetical: a sandbox that cannot see
# the source tree produces exactly a clean, zero-finding, exit-0 scan. Step 7 below
# turns that into a positive control instead of a trap.
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
#     fedora:41 bash /src/packaging/flatpak/verify-in-container.sh
#
# The named volume is worth using: the two runtimes are about 2.4 GB and reinstalling
# them on every run dwarfs the rest of the script.
set -euo pipefail

REPO="${REPO:-/src}"
OUT="${OUT:-/tmp/flatpakbuild}"
APP_ID="io.github.awslabs.automated_security_helper"
RUNTIME_VERSION="24.08"

# The fixture does NOT go in /tmp, and that is not a style choice. --filesystem=host
# grants every toplevel path under / except a reserved set, and /tmp, /var, /root, /boot,
# /efi and /sys are outside it -- an app sees its own tmpfs at /tmp, not the host's. A
# fixture in /tmp would therefore be invisible to the sandboxed scan, the scan would
# report zero findings, and the obvious conclusion would be that the manifest's grant is
# broken. /srv is an ordinary toplevel and is covered.
FIX=/srv/ash-fixture
FIX_UNREACHABLE=/tmp/ash-fixture-negative-control

echo "== 1. install build prerequisites"
if command -v dnf >/dev/null; then
  dnf -q -y install flatpak flatpak-builder findutils python3 >/dev/null 2>&1
elif command -v apt-get >/dev/null; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get -qq update >/dev/null
  apt-get -qq install -y --no-install-recommends \
    flatpak flatpak-builder ca-certificates python3 >/dev/null
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
flatpak install -y --system --noninteractive \
  flathub "org.freedesktop.Sdk//${RUNTIME_VERSION}" >/dev/null 2>&1 || true
flatpak info --system "org.freedesktop.Sdk//${RUNTIME_VERSION}" >/dev/null || {
  echo "   FAIL: org.freedesktop.Sdk//${RUNTIME_VERSION} is not installed" >&2
  exit 1
}
echo "   runtime: org.freedesktop.Sdk//${RUNTIME_VERSION}"
echo -n "   runtime python: "
flatpak run --command=python3 "org.freedesktop.Sdk//${RUNTIME_VERSION}" -V

echo "== 2. build the package"
WHEEL="$(find "$REPO/dist" -maxdepth 1 -name '*.whl' -print -quit)"
[ -n "$WHEEL" ] || { echo "   FAIL: no wheel in $REPO/dist" >&2; exit 1; }
echo "   wheel: $(basename "$WHEEL")"
BUNDLE="$("$REPO/packaging/flatpak/build.sh" "$WHEEL" "$OUT")"
echo "   built: $BUNDLE ($(du -h "$BUNDLE" | cut -f1))"

echo "== 3. install it"
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
# The entry-point contract: ash is canonical, ashv3 is deprecated and warns once on
# stderr, automated-security-helper is kept indefinitely and is silent. All three come
# from the wheel's [project.scripts], so a package that installed a subset would drop
# the escape-hatch name on exactly the hosts it exists for.
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
echo -n "   ash resolved inside the venv: "
flatpak run --command=sh "$APP_ID" -c 'command -v ash; readlink -f "$XDG_DATA_HOME" 2>/dev/null | head -1'

echo "== 7. negative control: a fixture the sandbox cannot reach must find nothing"
# Run BEFORE the real scan. This is the positive control for the whole verification:
# it proves that a zero-finding result is what an unreachable source tree looks like, so
# the non-zero result in step 8 is evidence the grant is doing work rather than evidence
# that detect-secrets fires on anything.
#
# /tmp is deliberately outside --filesystem=host, so the app sees its own empty tmpfs
# there and the planted secret is not in it.
rm -rf "$FIX_UNREACHABLE"; mkdir -p "$FIX_UNREACHABLE"
cat > "$FIX_UNREACHABLE/leak.py" <<'PY'
# Fixture for packaging verification. Not a real credential.
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
PY
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

echo "== 8. scan a reachable fixture with a KNOWN finding"
# detect-secrets is a runtime dependency of ASH and drives in process, so it is the one
# default scanner present after installing ASH alone. Everything else is correctly
# reported SKIPPED rather than MISSING.
rm -rf "$FIX"; mkdir -p "$FIX"
cat > "$FIX/leak.py" <<'PY'
# Fixture for packaging verification. Not a real credential.
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
PY
# --output-dir is NOT passed. ASH defaults it to <source-dir>/.ash/ash_output
# (cli/scan.py:636-640), which is inside the tree being scanned and therefore on the
# host. Letting it default is the part of the sandbox trade that a passed --output-dir
# would hide.
cd "$FIX"
echo -n "   CWD as the sandbox sees it: "
flatpak run --command=pwd "$APP_ID" || echo "(pwd not preserved)"
set +e
flatpak run "$APP_ID" scan --source-dir "$FIX" \
  --scanners detect-secrets --no-progress 2>&1 | tail -25
SCAN_RC=${PIPESTATUS[0]}
set -e
echo "   ash scan rc=$SCAN_RC"

echo "== 9. assert a finding was actually reported"
python3 - "$FIX" <<'PY'
import json, sys, pathlib
out = pathlib.Path(sys.argv[1]) / ".ash" / "ash_output"
if not out.exists():
    print(f"   FAIL: {out} was never created, so the default output directory --")
    print("   which lands inside the scanned tree -- was not writable from the sandbox.")
    raise SystemExit(1)
sarif = out / "reports" / "ash.sarif"
if not sarif.exists():
    cands = sorted(out.rglob("*.sarif"))
    if not cands:
        print("   FAIL: no SARIF produced, so nothing can be asserted about findings")
        raise SystemExit(1)
    sarif = cands[0]
doc = json.loads(sarif.read_text(encoding="utf-8"))
results = [r for run in doc.get("runs", []) for r in run.get("results", [])]
print(f"   SARIF: {sarif.name}, {len(results)} result(s)")
if not results:
    print("   FAIL: scan produced 0 findings on a fixture planted with a secret.")
    print("   A green scan that found nothing is the silent pass this branch removes.")
    raise SystemExit(1)
for r in results[:3]:
    loc = (r.get("locations") or [{}])[0]
    uri = loc.get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "?")
    print(f"     - {r.get('ruleId','?')} at {uri}")
print("   OK: the installed package ran a scan and reported findings")
PY

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
# This is where the Flatpak genuinely differs from the .deb and .rpm, whose removal
# steps assert the venv is gone. Flatpak keeps ~/.var/app/$FLATPAK_ID across an
# uninstall by design -- it is user data, not package content -- so the honest analogue
# of "removal drops the venv" is `--delete-data`. Both halves are measured rather than
# one being assumed.
flatpak uninstall -y --system --noninteractive "$APP_ID" >/dev/null 2>&1
if [ ! -d "$DATA_ROOT" ]; then
  echo "   FAIL: a plain uninstall deleted $DATA_ROOT. That contradicts what" >&2
  echo "   README.flatpak tells users about reclaiming the space, so the doc is now" >&2
  echo "   wrong." >&2
  exit 1
fi
echo "   OK: plain uninstall kept $DATA_ROOT ($(du -sh "$DATA_ROOT" | cut -f1))"

flatpak install -y --system --noninteractive --bundle "$BUNDLE" >/dev/null 2>&1
flatpak uninstall -y --system --noninteractive --delete-data "$APP_ID" >/dev/null 2>&1
if [ -d "$DATA_ROOT" ]; then
  echo "   FAIL: $DATA_ROOT survived --delete-data" >&2
  exit 1
fi
echo "   OK: --delete-data removed the venv the first run created"

echo
echo "FLATPAK VERIFICATION PASSED"
