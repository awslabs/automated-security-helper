#!/usr/bin/env bash
#
# Builds the JetBrains plugin, runs its tests, and checks what the build produced --
# the same requirement packaging/deb/verify-in-container.sh and
# packaging/rpm/verify-in-container.sh hold their packages to: a build that is exercised
# rather than syntax-checked. Intended to run INSIDE a container that has a JDK 21, git and
# python3, with the repository mounted; .github/workflows/ash-jetbrains-ci.yml uses
# gradle:jdk21 for exactly that toolset.
#
# The transferable rule from those two scripts, and the reason step 3 is written the way it
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

echo "== 3. build, test, and gate coverage"
# `check` pulls in unitTest, assertTestsRan and assertCoverage; buildPlugin pulls in the
# distribution and, via finalizedBy, assertDistributionContents. Every gate is a Gradle task
# rather than a step here, so `./gradlew check` gates on a developer's machine exactly as this
# script does -- and so there is one place to relax each of them rather than two.
./gradlew --no-daemon --console=plain check buildPlugin

echo "== 4. the test count and the annotation assertion, printed from the report"
# assertTestsRan already ran as part of `check`. Invoked again here, rather than
# reimplemented, so the numbers appear in this script's own output: the claim "161 tests ran
# and none was skipped" should be checkable by reading the log, not only by trusting an exit
# code. Reimplementing it in this file is the mistake to avoid -- a verification that exists
# twice drifts, and the copy nobody runs by hand is the one that rots.
python3 assert-tests-ran.py \
  --results build/test-results/unitTest \
  --test-classes build/classes/java/test \
  --require-suite io.github.awslabs.ash.jetbrains.AnnotationCountTest

echo "== 5. the fixture still carries the planted secret"
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

echo "== 6. the distribution's member list, printed in full"
# assertDistributionContents already ran as part of buildPlugin. Printed again here so the
# member list is in this script's own output: the claim "no third-party jars ship" should be
# checkable by reading the log, not only by trusting an exit code.
python3 assert-plugin-zip-contents.py --dist-dir build/distributions --own-jar-prefix ash-jetbrains

echo
echo "JETBRAINS PLUGIN VERIFICATION PASSED"
