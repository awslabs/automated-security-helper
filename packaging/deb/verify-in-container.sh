#!/usr/bin/env bash
#
# Builds the .deb, installs it, and runs a real scan -- the plan's requirement that a
# package be exercised rather than syntax-checked. Intended to run INSIDE a Debian or
# Ubuntu container with the repo mounted at /src and a built wheel in /src/dist.
#
# The scan must report a finding. A scan that exits 0 having found nothing is
# indistinguishable from a scan that never ran, which is the failure this whole
# branch's exit-code work exists to remove -- so asserting exit 0 alone would repeat
# the bug in the test.
set -euo pipefail

REPO="${REPO:-/src}"
OUT="${OUT:-/tmp/debbuild}"

echo "== 1. install build prerequisites"
export DEBIAN_FRONTEND=noninteractive
apt-get -qq update >/dev/null
apt-get -qq install -y --no-install-recommends \
  dpkg-dev python3 python3-venv python3-pip ca-certificates >/dev/null
echo "   dpkg-deb $(dpkg-deb --version | head -1 | awk '{print $NF}')"
echo "   $(python3 -V)"

echo "== 2. build the package"
WHEEL="$(find "$REPO/dist" -maxdepth 1 -name '*.whl' -print -quit)"
[ -n "$WHEEL" ] || { echo "   FAIL: no wheel in $REPO/dist" >&2; exit 1; }
echo "   wheel: $(basename "$WHEEL")"
DEB="$("$REPO/packaging/deb/build.sh" "$WHEEL" "$OUT")"
echo "   built: $DEB"

echo "== 3. package metadata is well formed"
dpkg-deb --field "$DEB" Package Version Architecture Depends
# The payload must be ASH's wheel and nothing else. This is the invariant check at the
# package layer: the contents gate covers the wheel, this covers what the .deb adds.
PAYLOAD_WHEELS="$(dpkg-deb --contents "$DEB" | grep -c '\.whl$' || true)"
echo "   wheels in package: $PAYLOAD_WHEELS"
[ "$PAYLOAD_WHEELS" -eq 1 ] || {
  echo "   FAIL: expected exactly 1 bundled wheel, found $PAYLOAD_WHEELS." >&2
  echo "   Bundling dependency wheels would put detect-secrets, a scanner, in a" >&2
  echo "   published artifact. See packaging/README.md." >&2
  exit 1
}

echo "== 4. install it"
apt-get -qq install -y "$DEB" >/dev/null 2>&1 || dpkg -i "$DEB" >/dev/null 2>&1 || true
# dpkg -i can leave the package unconfigured if a dependency is missing; force the
# configure so a broken postinst surfaces here rather than as a missing binary later.
apt-get -qq install -f -y >/dev/null 2>&1 || true
dpkg -l ash | tail -1

echo "== 5. the installed entry point works"
command -v ash
ash --version

echo "== 6. scan a fixture with a KNOWN finding"
FIX=/tmp/fixture
rm -rf "$FIX"; mkdir -p "$FIX"
# detect-secrets is a runtime dependency of ASH and drives in process, so it is the
# one default scanner present after installing ASH alone. Everything else is correctly
# reported SKIPPED rather than MISSING.
cat > "$FIX/leak.py" <<'PY'
# Fixture for packaging verification. Not a real credential.
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
PY
cd "$FIX"
set +e
ash scan --source-dir "$FIX" --output-dir "$FIX/.ash/ash_output" \
         --scanners detect-secrets --no-progress 2>&1 | tail -25
SCAN_RC=${PIPESTATUS[0]}
set -e
echo "   ash scan rc=$SCAN_RC"

echo "== 7. assert a finding was actually reported"
python3 - "$FIX" <<'PY'
import json, sys, pathlib
out = pathlib.Path(sys.argv[1]) / ".ash" / "ash_output"
sarif = out / "reports" / "ash.sarif"
if not sarif.exists():
    cands = sorted(p for p in out.rglob("*.sarif"))
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
    rule = r.get("ruleId", "?")
    loc = (r.get("locations") or [{}])[0]
    uri = loc.get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "?")
    print(f"     - {rule} at {uri}")
print("   OK: the installed package ran a scan and reported findings")
PY

echo "== 8. removal drops the venv postinst created"
apt-get -qq remove -y ash >/dev/null 2>&1 || dpkg -r ash >/dev/null 2>&1
if [ -d /usr/lib/ash/venv ]; then
  echo "   FAIL: /usr/lib/ash/venv survived removal" >&2
  exit 1
fi
echo "   OK: venv removed"

echo
echo "DEB VERIFICATION PASSED"
