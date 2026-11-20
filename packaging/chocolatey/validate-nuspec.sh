#!/usr/bin/env bash
#
# Validates packaging/chocolatey/ash.nuspec against NuGet's published .nuspec XSD.
#
# WHY THIS EXISTS
#
# The only tool that authoritatively validates a nuspec is `choco pack`, and that needs
# Windows. Everything about this package could therefore be wrong in a way nobody sees
# until a Windows job runs, which is the slowest possible feedback loop for a typo in a
# metadata file. The nuspec format is NuGet's, its schema is published, and xmllint can
# check a document against it in milliseconds on any machine.
#
# Run it the same way locally and in CI:
#
#   bash packaging/chocolatey/validate-nuspec.sh
#
# WHY THE SELF-TEST RUNS FIRST
#
# `xmllint` invoked without --schema parses the document and exits 0. So does xmllint
# handed a schema file it could not load, in some builds. Either mistake turns this
# script into a green light that checks nothing, and no amount of reading the output
# would reveal it, because "ash.nuspec validates" is exactly what a passing run prints.
#
# So before the real document is checked, two deliberately broken copies are checked
# and required to be REJECTED. This is the same reasoning as the "Prove the
# artifact-contents check can fail" step in .github/workflows/ash-package.yml, which
# runs before the build for the same reason: a matcher that silently stopped matching
# would otherwise clear every artifact forever.
#
# The two controls are chosen to fail through different parts of the schema:
#
#   missing-required-element   <id> deleted. Catches a schema that loaded but whose
#                              minOccurs constraints are not being applied.
#   undeclared-element         a <docsUrl> added. Chocolatey accepts that element and
#                              the NuGet XSD does not declare it, which is precisely
#                              the constraint the comment at the top of ash.nuspec
#                              relies on. If this control ever stops failing, that
#                              comment is wrong and the file may drift into
#                              Chocolatey-only metadata that only Windows can check.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
NUSPEC="${1:-$HERE/ash.nuspec}"

# The nuspec schema NuGet ships. It is a TEMPLATE, not a usable schema: targetNamespace
# and both default namespaces are the literal three characters {0}, which NuGet fills in
# at runtime with whichever nuspec namespace version the document declares. Handing it
# to xmllint unmodified fails with "Invalid URI" on the namespace, so the placeholder is
# substituted below. That substitution is the reason this cannot be a one-line
# `xmllint --schema <url>`.
XSD_URL="https://raw.githubusercontent.com/NuGet/NuGet.Client/dev/src/NuGet.Core/NuGet.Packaging/compiler/resources/nuspec.xsd"

# Pinned rather than read out of the document. Reading the namespace from the nuspec and
# substituting THAT into the schema would make any namespace validate, including a
# misspelled one, because the schema would be rebuilt to match whatever the document
# claimed. This is the version Chocolatey's own package template declares.
EXPECTED_NS="http://schemas.microsoft.com/packaging/2015/06/nuspec.xsd"

command -v xmllint >/dev/null || {
  echo "error: xmllint not found. It comes from libxml2-utils on Debian and Ubuntu," >&2
  echo "       and from libxml2 on Amazon Linux and RHEL." >&2
  exit 1
}
command -v curl >/dev/null || { echo "error: curl not found" >&2; exit 1; }
[ -f "$NUSPEC" ] || { echo "error: no such nuspec: $NUSPEC" >&2; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "== fetching the NuGet nuspec XSD"
# --fail so an HTTP error is an error rather than an error page written to the output
# file, and --retry because a transient 503 from a CDN must not read as a schema
# problem.
curl -sS --fail --retry 3 --retry-delay 2 -L "$XSD_URL" -o "$WORK/nuspec.template.xsd"
echo "   $(wc -c < "$WORK/nuspec.template.xsd") bytes from $XSD_URL"

# A fetch that returned something other than the schema must stop the run, not validate
# against it. Both checks matter: the first rules out an HTML error page served with a
# 200, the second rules out a future NuGet commit that resolves the namespace itself,
# after which the substitution below would silently do nothing and every namespace
# would validate.
grep -q '<xs:schema' "$WORK/nuspec.template.xsd" || {
  echo "error: what was fetched from $XSD_URL is not an XML schema." >&2
  head -c 200 "$WORK/nuspec.template.xsd" >&2; echo >&2
  exit 1
}
PLACEHOLDERS="$(grep -c '{0}' "$WORK/nuspec.template.xsd" || true)"
if [ "$PLACEHOLDERS" -eq 0 ]; then
  echo "error: the fetched XSD no longer contains the {0} namespace placeholder." >&2
  echo "       NuGet may have resolved it upstream. Re-read the file and drop the" >&2
  echo "       substitution below, rather than leaving a no-op sed in place." >&2
  exit 1
fi
sed "s|{0}|$EXPECTED_NS|g" "$WORK/nuspec.template.xsd" > "$WORK/nuspec.xsd"

echo "== the document declares the namespace this schema describes"
# Checked separately from the schema validation because it cannot be checked by it. The
# schema only ever sees documents in its own target namespace; one in a different
# namespace is not invalid, it is simply not described, and xmllint reports that as
# "No matching global declaration" -- a message that reads like a schema problem.
DECLARED_NS="$(xmllint --xpath 'namespace-uri(/*)' "$NUSPEC" 2>/dev/null || true)"
if [ "$DECLARED_NS" != "$EXPECTED_NS" ]; then
  echo "error: $NUSPEC declares namespace '$DECLARED_NS'," >&2
  echo "       expected '$EXPECTED_NS'." >&2
  exit 1
fi
echo "   $DECLARED_NS"

echo "== self-test: the validator must REJECT a broken nuspec"
selftest() {
  local label="$1" file="$2"
  if xmllint --noout --schema "$WORK/nuspec.xsd" "$file" >"$WORK/$label.log" 2>&1; then
    echo "   FAIL: $label was ACCEPTED. This validator is not checking anything." >&2
    echo "         Most likely --schema was dropped, or the schema failed to load." >&2
    exit 1
  fi
  echo "   OK: $label rejected -- $(grep -m1 -o 'element [^:]*: Schemas validity error.*' "$WORK/$label.log" || tail -n 1 "$WORK/$label.log")"
}

# minOccurs=1 on <id>, so deleting it must fail.
python3 - "$NUSPEC" "$WORK/missing-required-element.nuspec" <<'PY'
import re, sys
src, dst = sys.argv[1], sys.argv[2]
text = open(src, encoding="utf-8").read()
out, n = re.subn(r"[ \t]*<id>[^<]*</id>\n", "", text, count=1)
if n != 1:
    raise SystemExit("the self-test could not find an <id> element to delete")
open(dst, "w", encoding="utf-8").write(out)
PY
selftest "missing-required-element" "$WORK/missing-required-element.nuspec"

# <docsUrl> is Chocolatey metadata the NuGet XSD does not declare.
python3 - "$NUSPEC" "$WORK/undeclared-element.nuspec" <<'PY'
import re, sys
src, dst = sys.argv[1], sys.argv[2]
text = open(src, encoding="utf-8").read()
out, n = re.subn(
    r"(<id>[^<]*</id>\n)",
    r"\1    <docsUrl>https://example.invalid/docs</docsUrl>\n",
    text,
    count=1,
)
if n != 1:
    raise SystemExit("the self-test could not find an <id> element to insert after")
open(dst, "w", encoding="utf-8").write(out)
PY
selftest "undeclared-element" "$WORK/undeclared-element.nuspec"

echo "== validating $NUSPEC"
xmllint --noout --schema "$WORK/nuspec.xsd" "$NUSPEC"

echo
echo "NUSPEC SCHEMA VALIDATION PASSED"
