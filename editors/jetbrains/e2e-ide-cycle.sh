#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Installs, upgrades and uninstalls the built plugin zip in a real IDE, headless:
#
#   bash editors/jetbrains/e2e-ide-cycle.sh <work-dir>
#
#   E2E_PREV_REF  the git ref N-1 is built from (default origin/v4-capabilities). When it has
#                 HEAD's tree, as on a push to that branch, HEAD's first parent is used, the
#                 same rule scripts/e2e/wheel.sh follows.
#
# The IDE is the IntelliJ IDEA distribution the build resolved (printIdePath), started with
# its own launcher, bin/idea.sh, against a private config, system, plugins and log
# directory per leg (IDEA_PROPERTIES), so nothing touches the user's own IDE.
#
# 1. Builds N, the plugin zip from this checkout, and N-1, the plugin as committed at
#    E2E_PREV_REF with its version lowered (0.1.0 -> 0.0.0), so the upgrade crosses a real
#    version change and whatever code changed between the two.
# 2. Fresh install of N with the IDE's own installer, `idea.sh installPlugins <id> <repo>`,
#    from a local plugin repository (an updatePlugins.xml whose url is the built zip). The
#    installed jar must be byte-identical to the one in the zip, which also rules out the
#    installer having fetched something else from the Marketplace, which it queries as well.
# 3. Upgrade: N-1 installed and loaded, then replaced by N in the same IDE config (see
#    UPGRADE below). Afterwards only N's files may be on disk and N must be what loads.
# 4. Uninstall: the plugin's directory removed from the plugins directory. The headless
#    launcher has an installer and no uninstaller, so the directory is removed directly.
#    The next start must load no ASH plugin.
# 5. Negative controls, each seen failing: the loaded-version check asked for N while N-1 is
#    loaded, the same check after uninstall, and an install from a truncated zip.
# 6. Leaves two installs for e2e-installed-scan.sh, which scans through them: the fresh N from
#    step 2 and a separate N-1, each written by the installer and checked loaded, named in
#    <work-dir>/installed-plugins.env.
#
# "Loaded" is the IDE's own statement. At startup it logs "Loaded custom plugins: <name>
# (<version>)" for every enabled third-party plugin. The start used to read that line is
# `idea.sh format -h`, the bundled formatter's usage: a headless application start that
# loads every plugin and exits without needing a project.
#
# CONSENT. A third-party plugin installed headless is disabled at the next start until the
# user approves it, which a GUI start asks for once ("3rd-party plugin privacy note not
# accepted yet" in a headless log). installPlugins takes that approval as
# --give-consent-to-use-third-party-plugins, and this script passes it.
#
# UPGRADE. The headless installer does not upgrade: given a plugin that is already
# installed, it prints "already installed: <id>" and leaves N-1 in place (measured on
# 2025.2.5). The in-place update the GUI performs is applied by the IDE at restart and has
# no headless entry point. So the upgrade leg removes N-1 the way step 4 uninstalls, then
# installs N into the same IDE config and system directories, which is what a scripted
# upgrade has to do, and checks that only N is left and loaded.
#
# Nothing is published. The repository is a file on disk, and the N-1 zip carries a version
# that was never released.
set -euo pipefail

WORK="${1:?usage: e2e-ide-cycle.sh <work-dir>}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
PREV_REF="${E2E_PREV_REF:-origin/v4-capabilities}"

# Never as root, for the reason verify-in-container.sh gives; Gradle builds both zips here.
if [ "$(id -u)" = 0 ]; then
  exec bash "$HERE/run-unprivileged.sh" bash "$HERE/e2e-ide-cycle.sh" "$@"
fi

say() { printf '== %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

mkdir -p "$WORK"
WORK="$(cd "$WORK" && pwd)"

descriptor_field() {
  python3 - "$HERE/src/main/resources/META-INF/plugin.xml" "$1" <<'PY'
import re, sys
text = open(sys.argv[1], encoding="utf-8").read()
match = re.search(r"<%s>([^<]+)</%s>" % (sys.argv[2], sys.argv[2]), text)
if not match:
    sys.exit(f"no <{sys.argv[2]}> in {sys.argv[1]}")
print(match.group(1).strip())
PY
}
PLUGIN_ID="$(descriptor_field id)"
PLUGIN_NAME="$(descriptor_field name)"

gradle_version() { sed -n 's/^version = "\(.*\)"$/\1/p' "$1/build.gradle.kts" | head -n 1; }
HEAD_VERSION="$(gradle_version "$HERE")"
[ -n "$HEAD_VERSION" ] || fail "no version line in build.gradle.kts"

# --------------------------------------------------------------------------
# 1. Build N and N-1.
# --------------------------------------------------------------------------
cd "$HERE"
IDE="$(./gradlew -q --no-daemon --console=plain printIdePath | tail -n 1)"
[ -x "$IDE/bin/idea.sh" ] || fail "printIdePath gave $IDE, which has no bin/idea.sh"
say "IDE: $(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d["name"], d["version"], d["buildNumber"])' "$IDE/product-info.json") at $IDE"

say "build N ($HEAD_VERSION) from this checkout"
./gradlew --no-daemon --console=plain -q buildPlugin
HEAD_ZIP="$HERE/build/distributions/ash-jetbrains-$HEAD_VERSION.zip"
[ -f "$HEAD_ZIP" ] || fail "buildPlugin wrote no $HEAD_ZIP"

HEAD_SHA="$(git -C "$REPO" rev-parse HEAD)"
PREV_SHA="$(git -C "$REPO" rev-parse --verify --quiet "$PREV_REF^{commit}")" \
  || fail "E2E_PREV_REF $PREV_REF does not name a commit"
tree_of() { git -C "$REPO" rev-parse "$1^{tree}"; }
if [ "$(tree_of "$PREV_SHA")" = "$(tree_of HEAD)" ]; then
  say "$PREV_REF has HEAD's tree; using HEAD's first parent as N-1"
  PREV_REF="HEAD^"
  PREV_SHA="$(git -C "$REPO" rev-parse --verify --quiet "HEAD^1^{commit}")" \
    || fail "HEAD has no parent in this clone; fetch at least one more commit of history"
fi
if git -C "$REPO" diff --quiet "$PREV_SHA" HEAD -- editors/jetbrains; then
  say "editors/jetbrains is unchanged between $PREV_REF and HEAD; the upgrade crosses a version change only"
fi

PREV_SRC="$WORK/src-prev"
rm -rf "$PREV_SRC"
mkdir -p "$PREV_SRC"
# The shared payload rules come too: assert-plugin-zip-contents.py, which buildPlugin runs,
# imports them from .github/scripts rather than carrying a copy.
git -C "$REPO" archive "$PREV_SHA" editors/jetbrains .github/scripts/assert-artifact-contents.py | tar -x -C "$PREV_SRC"
PREV_DIR="$PREV_SRC/editors/jetbrains"
PREV_BASE_VERSION="$(gradle_version "$PREV_DIR")"
[ -n "$PREV_BASE_VERSION" ] || fail "no version line in $PREV_REF's build.gradle.kts"
# The last non-zero component decremented, as scripts/e2e/wheel.sh does for the wheel.
PREV_VERSION="$(printf '%s\n' "$PREV_BASE_VERSION" | awk -F. '{
  n = NF; while (n > 0 && $n == 0) n--;
  if (n == 0) { exit 1 }
  $n = $n - 1; for (i = n + 1; i <= NF; i++) $i = 0;
  out = $1; for (i = 2; i <= NF; i++) out = out "." $i; print out }')" \
  || fail "cannot derive a lower version from $PREV_BASE_VERSION"
python3 - "$PREV_DIR/build.gradle.kts" "$PREV_BASE_VERSION" "$PREV_VERSION" <<'PY'
import sys
path, old, new = sys.argv[1:]
text = open(path, encoding="utf-8").read()
needle = f'\nversion = "{old}"\n'
if text.count(needle) != 1:
    sys.exit(f"expected exactly one version line {old!r} in {path}")
open(path, "w", encoding="utf-8", newline="").write(text.replace(needle, f'\nversion = "{new}"\n'))
PY
python3 - "$PREV_VERSION" "$HEAD_VERSION" <<'PY' \
  || fail "N-1 version $PREV_VERSION does not sort below N's $HEAD_VERSION"
import re, sys
prev, head = sys.argv[1:]
for v in (prev, head):
    if not re.fullmatch(r"[0-9]+(\.[0-9]+)*", v):
        sys.exit(f"version {v!r} is not dotted integers")
key = lambda v: [int(p) for p in v.split(".")] + [0] * 8
sys.exit(0 if key(prev) < key(head) else 1)
PY
say "build N-1 ($PREV_VERSION) from $PREV_REF ($PREV_SHA); N is $HEAD_SHA"
(cd "$PREV_DIR" && ./gradlew --no-daemon --console=plain -q buildPlugin)
PREV_ZIP="$PREV_DIR/build/distributions/ash-jetbrains-$PREV_VERSION.zip"
[ -f "$PREV_ZIP" ] || fail "buildPlugin wrote no $PREV_ZIP"

# --------------------------------------------------------------------------
# The IDE harness.
# --------------------------------------------------------------------------

# A private IDE home: config, system, plugins and logs, and the properties file naming them.
new_home() {
  local home="$WORK/ide-$1"
  rm -rf "$home"
  mkdir -p "$home/config" "$home/system" "$home/plugins" "$home/repo"
  {
    printf 'idea.config.path=%s\n' "$home/config"
    printf 'idea.system.path=%s\n' "$home/system"
    printf 'idea.plugins.path=%s\n' "$home/plugins"
    printf 'idea.log.path=%s\n' "$home/log"
  } > "$home/idea.properties"
  printf '%s\n' "$home"
}

# Runs the IDE launcher against <home>; its output goes to <home>/last.out and the log of
# this start alone to <home>/log/idea.log.
ide() {
  local home="$1"
  shift
  rm -rf "$home/log"
  IDEA_PROPERTIES="$home/idea.properties" timeout 600 "$IDE/bin/idea.sh" "$@" > "$home/last.out" 2>&1
}

# The single top-level directory of a plugin zip, which is the directory it installs as.
zip_dir() {
  python3 - "$1" <<'PY'
import sys, zipfile
tops = {n.split("/", 1)[0] for n in zipfile.ZipFile(sys.argv[1]).namelist()}
if len(tops) != 1:
    sys.exit(f"{sys.argv[1]} has {len(tops)} top-level entries, expected one: {sorted(tops)}")
print(tops.pop())
PY
}

# Installs <zip> as <version> through the IDE's own headless installer.
install() {
  local home="$1" zip="$2" version="$3"
  cat > "$home/repo/updatePlugins.xml" <<XML
<plugins>
  <plugin id="$PLUGIN_ID" url="file://$zip" version="$version">
    <idea-version since-build="252"/>
  </plugin>
</plugins>
XML
  if ! ide "$home" installPlugins "$PLUGIN_ID" "file://$home/repo/updatePlugins.xml" --give-consent-to-use-third-party-plugins; then
    tail -n 20 "$home/last.out" >&2
    printf 'installPlugins exited non-zero for %s\n' "$zip" >&2
    return 1
  fi
  if ! grep -q "installed plugin: PluginNode{id=$PLUGIN_ID," "$home/last.out"; then
    grep -v '^\s*at ' "$home/last.out" | tail -n 20 >&2
    printf 'installPlugins did not report installing %s from %s\n' "$PLUGIN_ID" "$zip" >&2
    return 1
  fi
}

# Removes the installed plugin's directory from <home>/plugins.
uninstall() {
  local home="$1" dir
  dir="$(zip_dir "$HEAD_ZIP")"
  [ -d "$home/plugins/$dir" ] || fail "no $home/plugins/$dir to uninstall"
  rm -rf "${home:?}/plugins/${dir:?}"
}

# Exactly the jar inside <zip> is installed under <home>/plugins, byte for byte.
assert_installed() {
  python3 - "$1/plugins" "$2" <<'PY'
import hashlib, pathlib, sys, zipfile
plugins, zip_path = pathlib.Path(sys.argv[1]), sys.argv[2]
archive = zipfile.ZipFile(zip_path)
expected = {n: hashlib.sha256(archive.read(n)).hexdigest() for n in archive.namelist() if not n.endswith("/")}
top = next(iter(expected)).split("/", 1)[0]
root = plugins / top
if not root.is_dir():
    sys.exit(f"no {root}; the plugin is not installed")
found = {p.relative_to(plugins).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in root.rglob("*") if p.is_file()}
if found != expected:
    extra = sorted(set(found) - set(expected))
    missing = sorted(set(expected) - set(found))
    changed = sorted(n for n in set(found) & set(expected) if found[n] != expected[n])
    sys.exit(f"installed files differ from {zip_path}: extra {extra}, missing {missing}, changed {changed}")
others = sorted(p.name for p in plugins.iterdir() if p.name != top)
if others:
    sys.exit(f"other entries in {plugins}: {others}")
print(f"   installed: {', '.join(sorted(found))} (identical to {pathlib.Path(zip_path).name})")
PY
}

# The versions of <name> in this start's "Loaded custom plugins" line, one per line.
loaded_versions() {
  python3 - "$1/log/idea.log" "$PLUGIN_NAME" <<'PY'
import re, sys
log, name = sys.argv[1:]
text = open(log, encoding="utf-8", errors="replace").read()
if "Loaded bundled plugins:" not in text:
    sys.exit(f"{log} has no 'Loaded bundled plugins' line; the IDE did not get through plugin loading")
for line in text.splitlines():
    if "Loaded custom plugins:" in line:
        for version in re.findall(re.escape(name) + r" \(([^)]*)\)", line):
            print(version)
PY
}

# Starts the IDE and requires exactly <version> of the plugin to be loaded.
assert_loaded() {
  local home="$1" want="$2" got
  ide "$home" format -h || { tail -n 20 "$home/last.out" >&2; printf 'the IDE failed to start\n' >&2; return 1; }
  got="$(loaded_versions "$home")" || return 1
  if [ "$got" != "$want" ]; then
    printf 'the IDE loaded %s version(s) [%s], expected exactly [%s]\n' "$PLUGIN_NAME" "${got//$'\n'/, }" "$want" >&2
    return 1
  fi
  printf '   the IDE loaded %s (%s)\n' "$PLUGIN_NAME" "$got"
}

assert_not_loaded() {
  local home="$1" got
  ide "$home" format -h || { tail -n 20 "$home/last.out" >&2; printf 'the IDE failed to start\n' >&2; return 1; }
  got="$(loaded_versions "$home")" || return 1
  if [ -n "$got" ]; then
    printf 'the IDE still loaded %s [%s]\n' "$PLUGIN_NAME" "${got//$'\n'/, }" >&2
    return 1
  fi
  printf '   the IDE loaded no %s plugin\n' "$PLUGIN_NAME"
}

# Runs a check that must fail, and fails if it passes.
must_fail() {
  local label="$1"
  shift
  if ( "$@" ) > "$WORK/negative.out" 2>&1; then
    cat "$WORK/negative.out"
    fail "negative control '$label' passed; the check cannot fail"
  fi
  printf '   negative control failed as required (%s): %s\n' "$label" "$(tail -n 1 "$WORK/negative.out")"
}

# --------------------------------------------------------------------------
# 2. Fresh install of N.
# --------------------------------------------------------------------------
say "fresh IDE: no ASH plugin before the install"
FRESH="$(new_home fresh)"
assert_not_loaded "$FRESH"
say "fresh install of N ($HEAD_VERSION)"
install "$FRESH" "$HEAD_ZIP" "$HEAD_VERSION" || fail "installing N into a fresh IDE failed"
assert_installed "$FRESH" "$HEAD_ZIP"
assert_loaded "$FRESH" "$HEAD_VERSION" || fail "a fresh install of N is not what the IDE loads"
# Nothing below touches $FRESH again, so e2e-installed-scan.sh scans through this install.

# --------------------------------------------------------------------------
# 3. Upgrade N-1 -> N.
# --------------------------------------------------------------------------
say "install N-1 ($PREV_VERSION)"
UPGRADE="$(new_home upgrade)"
install "$UPGRADE" "$PREV_ZIP" "$PREV_VERSION" || fail "installing N-1 failed"
assert_installed "$UPGRADE" "$PREV_ZIP"
assert_loaded "$UPGRADE" "$PREV_VERSION" || fail "N-1 is not what the IDE loads"
must_fail "N expected while N-1 is loaded" assert_loaded "$UPGRADE" "$HEAD_VERSION"

say "upgrade to N ($HEAD_VERSION): remove N-1, install N into the same IDE config"
uninstall "$UPGRADE"
install "$UPGRADE" "$HEAD_ZIP" "$HEAD_VERSION" || fail "installing N where N-1 was failed"
assert_installed "$UPGRADE" "$HEAD_ZIP"
assert_loaded "$UPGRADE" "$HEAD_VERSION" || fail "after the upgrade the IDE does not load N"

# --------------------------------------------------------------------------
# 4. Uninstall.
# --------------------------------------------------------------------------
say "uninstall"
uninstall "$UPGRADE"
assert_not_loaded "$UPGRADE" || fail "the IDE still loads the plugin after it was uninstalled"
must_fail "N expected after uninstall" assert_loaded "$UPGRADE" "$HEAD_VERSION"

# --------------------------------------------------------------------------
# 5. A broken artifact must not install.
# --------------------------------------------------------------------------
say "negative control: a truncated zip"
CORRUPT_ZIP="$WORK/ash-jetbrains-corrupt.zip"
python3 - "$HEAD_ZIP" "$CORRUPT_ZIP" <<'PY'
import sys
data = open(sys.argv[1], "rb").read()
open(sys.argv[2], "wb").write(data[: len(data) // 2])
PY
CORRUPT="$(new_home corrupt)"
must_fail "install from a truncated zip" install "$CORRUPT" "$CORRUPT_ZIP" "$HEAD_VERSION"
must_fail "loaded after a failed install" assert_loaded "$CORRUPT" "$HEAD_VERSION"

# --------------------------------------------------------------------------
# 6. The installs e2e-installed-scan.sh scans through.
# --------------------------------------------------------------------------
say "install N-1 ($PREV_VERSION) on its own, for the installed-zip scan's negative control"
PREV="$(new_home prev)"
install "$PREV" "$PREV_ZIP" "$PREV_VERSION" || fail "installing N-1 for the installed-zip scan failed"
assert_installed "$PREV" "$PREV_ZIP"
assert_loaded "$PREV" "$PREV_VERSION" || fail "the separate N-1 install is not what the IDE loads"
assert_installed "$FRESH" "$HEAD_ZIP"
PLUGIN_DIR="$(zip_dir "$HEAD_ZIP")"
{
  printf 'HEAD_VERSION=%q\n' "$HEAD_VERSION"
  printf 'HEAD_ZIP=%q\n' "$HEAD_ZIP"
  printf 'HEAD_PLUGIN_DIR=%q\n' "$FRESH/plugins/$PLUGIN_DIR"
  printf 'PREV_VERSION=%q\n' "$PREV_VERSION"
  printf 'PREV_ZIP=%q\n' "$PREV_ZIP"
  printf 'PREV_PLUGIN_DIR=%q\n' "$PREV/plugins/$PLUGIN_DIR"
} > "$WORK/installed-plugins.env"
printf '   recorded in %s\n' "$WORK/installed-plugins.env"

echo
echo "JETBRAINS IDE INSTALL CYCLE PASSED: fresh $HEAD_VERSION, upgrade $PREV_VERSION -> $HEAD_VERSION, uninstall, 4 negative controls"
