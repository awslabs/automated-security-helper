#!/usr/bin/env bash
#
# Builds the JetBrains plugin, runs its tests, and checks what the build produced --
# the same requirement packaging/deb/verify-in-container.sh and
# packaging/rpm/verify-in-container.sh hold their packages to: a build that is exercised
# rather than syntax-checked. Intended to run INSIDE a container that has a JDK 21, git,
# python3 and curl, with the repository mounted; .github/workflows/ash-jetbrains-ci.yml uses
# gradle:jdk21 for exactly that toolset. curl joined that list when step 3 did: the two
# coverage gates parse XML through defusedxml, and this image has no package manager to
# install it with.
#
# The transferable rule from those two scripts, and the reason step 4 is written the way it
# is: an ASH scan that finds nothing exits 0. Measured on a real run of a clean tree -- exit
# code 0, SARIF with zero results. So "the build succeeded", "the tests ran" and "a report
# appeared" are each satisfied by a plugin that shows the user nothing over a real
# credential. Only a NON-ZERO count of annotations separates those.
#
# WHY THIS SCRIPT EXISTS RATHER THAN THE STEPS BEING WRITTEN IN YAML
#
# Same reason the deb and rpm jobs give: a verification that exists twice drifts, and the
# copy in CI is the one nobody runs by hand. Everything below runs identically on a
# developer's machine.
#
# WHAT IS DELIBERATELY NOT DONE HERE
#
# Nothing is published. There is no publishPlugin task wired to a token, no Marketplace
# submission, and no registry of any kind. The build resolves an IDE distribution from
# JetBrains' CDN, uses it to compile, and throws it away.
set -euo pipefail

# The plugin directory, resolved from this script rather than from the caller's cwd, so it
# works whether it is invoked as ./verify-in-container.sh or by absolute path.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

echo "== 1. record the toolchain, so a later failure can be attributed"
java -version 2>&1 | head -2 | sed 's/^/   /'
echo "   $(python3 -V)"
echo "   $(git --version)"
# The wrapper, not a system gradle. The wrapper pins the Gradle version; a system gradle is
# whatever the image happened to ship, and the IntelliJ Platform Gradle plugin refuses to
# apply below Gradle 9.0.0 -- which is how the wrapper's version was chosen, after 8.14.3
# produced exactly that error.
./gradlew --version 2>&1 | grep -E '^(Gradle|Launcher JVM)' | sed 's/^/   /'

echo "== 2. the wrapper jar is present, because a wrapper without it cannot bootstrap"
# Checked explicitly and early. .gitignore in this repository has bare extension rules that
# have already destroyed two agents' files: `*.spec` swallowed packaging/rpm/ash.spec, which
# was written, verified against, and never committed, and the rpm CI job could not pass. A
# gradle-wrapper.jar is conventionally both committed and gitignored, so this is the same
# trap one directory over. `git add` skips ignored files SILENTLY, so the only way to know is
# to ask.
WRAPPER_JAR="gradle/wrapper/gradle-wrapper.jar"
[ -f "$WRAPPER_JAR" ] || { echo "   FAIL: $WRAPPER_JAR is missing" >&2; exit 1; }
if ! git ls-files --error-unmatch "$WRAPPER_JAR" >/dev/null 2>&1; then
  echo "   FAIL: $WRAPPER_JAR exists but is not tracked by git." >&2
  echo "   A clean checkout would have no wrapper jar, ./gradlew would fail, and this job" >&2
  echo "   could not run. Check .gitignore for a rule that swallows it." >&2
  exit 1
fi
echo "   OK: $WRAPPER_JAR is tracked ($(wc -c < "$WRAPPER_JAR") bytes)"

echo "== 3. provision the one Python dependency the two gates need"
# assert-coverage.py and assert-tests-ran.py parse XML through defusedxml rather than
# xml.etree, so this container has to supply it. The image is gradle:jdk21, which has python3
# and -- measured, not assumed -- no pip, no ensurepip and no uv. So the wheel is fetched and
# unpacked directly. defusedxml is pure Python (py2.py3-none-any), which makes unpacking the
# wheel the whole install: nothing to compile, no entry points to generate.
#
# Pinned by sha256 rather than by version alone. This is a security scanner's own build, and a
# fetch that trusts whatever the index hands back is the shape of problem this repository
# exists to find.
#
# THIS STEP MUST FAIL THE BUILD IF IT CANNOT COMPLETE, and it does, three ways: `set -euo
# pipefail` is in force from the top of this file, `curl -f` turns an HTTP error into a
# non-zero exit, and `sha256sum -c` exits non-zero on a digest mismatch. Neither gate has a
# fallback to xml.etree either -- both import defusedxml at module scope and stop with a
# diagnostic if it is absent (assert-coverage.py exits 2, "could not run its checks at all";
# assert-tests-ran.py exits 1, the only failure code it defines). Measured in this image with
# nothing provisioned: a HEALTHY test-results fixture exits 1 rather than reporting a count.
#
# That combination is deliberate and is the point of the whole change: a gate that quietly
# degraded to the standard library when the network hiccuped would be strictly worse than the
# B314 suppression it replaced, because it would still print PASSED.
DEFUSEDXML_WHEEL_URL="https://files.pythonhosted.org/packages/07/6c/aa3f2f849e01cb6a001cd8554a88d4c77c5c1a31c95bdf1cf9301e6d9ef4/defusedxml-0.7.1-py2.py3-none-any.whl"
DEFUSEDXML_WHEEL_SHA256="a352e7e428770286cc899e2542b6cdaedb2b4953ff269a210103ec58f6198a61"
VENDOR="$HERE/build/python-vendor"
rm -rf "$VENDOR"
mkdir -p "$VENDOR"
curl -fsSL -o "$VENDOR/defusedxml.whl" "$DEFUSEDXML_WHEEL_URL"
echo "$DEFUSEDXML_WHEEL_SHA256  $VENDOR/defusedxml.whl" | sha256sum -c -
# `python3 -m zipfile` rather than `unzip`, which the image does not ship.
python3 -m zipfile -e "$VENDOR/defusedxml.whl" "$VENDOR"
# Exported, so it reaches the gates Gradle runs as well as the ones invoked directly below.
# assertCoverage and assertTestsRan are Gradle Exec tasks whose commandLine starts with
# "python3", and Gradle inherits this environment, so build.gradle.kts needs no change and no
# network access is added inside the Gradle build itself.
export PYTHONPATH="$VENDOR${PYTHONPATH:+:$PYTHONPATH}"
python3 -c 'import defusedxml; print("   defusedxml " + defusedxml.__version__ + " ready at " + defusedxml.__file__)'

echo "== 4. build, test, and gate coverage"
# `check` pulls in unitTest, assertTestsRan and assertCoverage; buildPlugin pulls in the
# distribution and, via finalizedBy, assertDistributionContents. Every gate is a Gradle task
# rather than a step here, so `./gradlew check` gates on a developer's machine exactly as this
# script does -- and so there is one place to relax each of them rather than two.
./gradlew --no-daemon --console=plain check buildPlugin

echo "== 5. the test count and the annotation assertion, printed from the report"
# assertTestsRan already ran as part of `check`. Invoked again here, rather than
# reimplemented, so the numbers appear in this script's own output: the claim "161 tests ran
# and none was skipped" should be checkable by reading the log, not only by trusting an exit
# code. Reimplementing it in this file is the mistake to avoid -- a verification that exists
# twice drifts, and the copy nobody runs by hand is the one that rots.
python3 assert-tests-ran.py \
  --results build/test-results/unitTest \
  --test-classes build/classes/java/test \
  --require-suite io.github.awslabs.ash.jetbrains.AnnotationCountTest

echo "== 6. the fixture still carries the planted secret"
# Without it, AnnotationCountTest passes vacuously: the SARIF fixture would still have three
# results, the planner would still place them, and nothing would be verifying that the value
# a scanner reacts to is present. The same value is planted by
# packaging/deb/verify-in-container.sh, packaging/rpm/verify-in-container.sh and
# Formula/ash.rb, so the whole branch has one known secret to look for.
FIXTURE="src/test/resources/fixtures/leak.py"
if ! grep -q 'wJalrXUtnFEMI' "$FIXTURE"; then
  echo "   FAIL: $FIXTURE no longer contains the planted example key." >&2
  echo "   Removing it to quieten a scanner would make the annotation-count assertion" >&2
  echo "   vacuous, which is the silent pass it exists to remove." >&2
  exit 1
fi
echo "   OK: $FIXTURE carries the example key the SARIF fixture was produced from"

echo "== 7. the distribution's member list, printed in full"
# assertDistributionContents already ran as part of buildPlugin. Printed again here so the
# member list is in this script's own output: the claim "no third-party jars ship" should be
# checkable by reading the log, not only by trusting an exit code.
python3 assert-plugin-zip-contents.py --dist-dir build/distributions --own-jar-prefix ash-jetbrains

echo
echo "JETBRAINS PLUGIN VERIFICATION PASSED"
