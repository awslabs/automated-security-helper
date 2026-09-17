#!/usr/bin/env bash
#
# Builds the .rpm, installs it, and runs a real scan -- the plan's requirement that a
# package be exercised rather than syntax-checked. Intended to run INSIDE an
# amazonlinux:2023 or ubi9 container with the repo mounted at /src and a wheel in
# /src/dist.
#
# The scan must report a finding. A scan that exits 0 having found nothing is
# indistinguishable from a scan that never ran, so asserting exit 0 alone would repeat
# in the test the bug this branch removes.
set -euo pipefail

REPO="${REPO:-/src}"
OUT="${OUT:-/tmp/rpmbuild-out}"

echo "== 1. install build prerequisites"
# Deliberately does NOT install any python3.1x. The package declares
# (python3.11 or python3.12 or python3.13) and dnf must satisfy that itself at step 4 --
# pre-installing an interpreter here would mask an unsatisfiable dependency, which is
# exactly the defect this verification caught on the first attempt.
dnf -q -y install rpm-build findutils >/dev/null 2>&1
echo "   rpmbuild $(rpmbuild --version | awk '{print $NF}')"
echo "   system python3 (below ASH's floor, on purpose): $(python3 -V 2>&1 || echo none)"

echo "== 2. build the package"
WHEEL="$(find "$REPO/dist" -maxdepth 1 -name '*.whl' -print -quit)"
[ -n "$WHEEL" ] || { echo "   FAIL: no wheel in $REPO/dist" >&2; exit 1; }
echo "   wheel: $(basename "$WHEEL")"
# The repo is mounted read-only, so build.sh is copied out first -- rpmbuild needs a
# writable _topdir and mktemp handles that, but the spec dir itself is read from /src.
RPM="$("$REPO/packaging/rpm/build.sh" "$WHEEL" "$OUT")"
echo "   built: $RPM"

echo "== 3. package metadata is well formed"
rpm -qp --qf 'Name: %{NAME}\nVersion: %{VERSION}\nRelease: %{RELEASE}\nArch: %{ARCH}\n' "$RPM" 2>/dev/null
echo -n "   Requires: "; rpm -qp --requires "$RPM" 2>/dev/null | tr '\n' ' ' ; echo
# The payload must be ASH's wheel and nothing else -- the invariant check at the
# package layer. The contents gate covers the wheel; this covers what the rpm adds.
PAYLOAD_WHEELS="$(rpm -qp --list "$RPM" 2>/dev/null | grep -c '\.whl$' || true)"
echo "   wheels in package: $PAYLOAD_WHEELS"
[ "$PAYLOAD_WHEELS" -eq 1 ] || {
  echo "   FAIL: expected exactly 1 bundled wheel, found $PAYLOAD_WHEELS." >&2
  echo "   Bundling dependency wheels would put detect-secrets, a scanner, in a" >&2
  echo "   published artifact. See packaging/README.md." >&2
  exit 1
}

echo "== 4. install it -- dnf must resolve the interpreter dependency itself"
dnf -y install "$RPM" 2>&1 | grep -Ei 'Installing|python3\.|Error|Complete' | head -12
rpm -q ash
echo "   interpreter dnf pulled in:"
rpm -qa 'python3.1*' --qf '     %{NAME} %{VERSION}\n' | sort | head -4
echo "   interpreter the venv was actually built with:"
readlink -f /usr/lib/ash/venv/bin/python3 2>/dev/null || echo "     (venv missing)"
/usr/lib/ash/venv/bin/python3 -V 2>/dev/null || true

echo "== 5. the installed entry point works"
command -v ash
ash --version

echo "== 6. scan a fixture with a KNOWN finding"
FIX=/tmp/fixture
rm -rf "$FIX"; mkdir -p "$FIX"
# detect-secrets is a runtime dependency of ASH and drives in process, so it is the one
# default scanner present after installing ASH alone. The rest are correctly reported
# SKIPPED rather than MISSING.
cat > "$FIX/leak.py" <<'PY'
# Fixture for packaging verification. Not a real credential.
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
PY
cd "$FIX"
set +e
ash scan --source-dir "$FIX" --output-dir "$FIX/.ash/ash_output" \
         --scanners detect-secrets --no-progress >/tmp/scan.log 2>&1
SCAN_RC=$?
set -e
tail -4 /tmp/scan.log
echo "   ash scan rc=$SCAN_RC"

echo "== 7. assert a finding was actually reported"
python3 - "$FIX" <<'PY'
import json, sys, pathlib
out = pathlib.Path(sys.argv[1]) / ".ash" / "ash_output"
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
    raise SystemExit(1)
for r in results[:3]:
    loc = (r.get("locations") or [{}])[0]
    uri = loc.get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "?")
    print(f"     - {r.get('ruleId','?')} at {uri}")
print("   OK: the installed package ran a scan and reported findings")
PY

echo "== 8. an UPGRADE must not delete the venv (postun \$1 check)"
# rpm runs the old package's %postun after the new one's %post, so a %postun that
# removes the venv unconditionally breaks every upgrade. Reinstall exercises the same
# ordering.
dnf -q -y reinstall "$RPM" >/dev/null 2>&1 || rpm -U --replacepkgs "$RPM"
if [ ! -x /usr/lib/ash/venv/bin/ash ]; then
  echo "   FAIL: the venv did not survive a reinstall -- %postun is missing its \$1 guard" >&2
  exit 1
fi
ash --version >/dev/null && echo "   OK: venv survived, ash still runs"

echo "== 9. erase drops the venv %post created"
dnf -q -y remove ash >/dev/null 2>&1 || rpm -e ash
if [ -d /usr/lib/ash/venv ]; then
  echo "   FAIL: /usr/lib/ash/venv survived erase" >&2
  exit 1
fi
echo "   OK: venv removed on erase"

echo
echo "RPM VERIFICATION PASSED"
