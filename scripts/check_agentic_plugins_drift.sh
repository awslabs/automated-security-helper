#!/usr/bin/env bash
# Drift check for the agentic-plugins outputs, written for a kit script step (entry=script).
#
# What it does: the byte comparison that `agentic-plugins check --drift-only` makes, run under
# the interpreter in <tree>/.venv. It builds every backend of
# ash-agent-plugins/agentic-coding/transpiler into a temporary directory, then byte-compares
# the result, and the universal AGENTS.md, against the files on disk. It calls
# transpiler.orchestrator.check_drift() directly so that it needs no `uv` (a kit step refuses
# `uv run`) and no entry point on PATH.
#
# On disk equals committed only in a clean checkout: check_drift() reads the filesystem, so an
# untracked or ignored file under the output paths reads as drift and an uncommitted
# regeneration reads as a pass. The script therefore runs `git status --porcelain --ignored`
# over ash-agent-plugins/agentic-coding/plugins and skills first, and exits 2 when it prints
# anything. The inputs get the same refusal: the check renders from
# ash-agent-plugins/agentic-coding/transpiler on disk (_base with its references/*.md glob,
# the templates, the transpiler code), so an uncommitted edit or an untracked file there
# makes the verdict one no commit holds. That status runs without --ignored, because the
# transpiler directory holds ignored files in any working tree (.venv, __pycache__, uv
# caches) and ignored files there are not inputs to the render.
#
# The bytes match CI's only when the render-path packages match. CI resolves them from the
# transpiler's uv.lock; this script uses the ones installed in <tree>/.venv. The output depends
# on jinja2 (with markupsafe) and PyYAML, so the script prints the interpreter version, their
# installed versions and their uv.lock pins on the VERSIONS, INSTALLED and PINS lines of
# drift.out, and exits 2 when any of the three differs from its pin or is not installed. The
# interpreter version and every other dependency are not compared.
#
# What it does not do: the schema-validation half of `agentic-plugins check` imports
# python-frontmatter, which the ASH virtual environment does not carry. Installing it is not
# allowed in a kit step, so that half is not run here.
#
# Contract (kit script step): run as `bash <copy of this file> <res dir>` with the tree as the
# working directory. No other argument. Read-only on the tree: no network, no install, no write
# outside <res dir> and the temporary directory the drift check makes under TMPDIR.
# Writes <res dir>/rc.txt with one line, "agentic-plugins-drift <rc> files=<n>", where n is the
# number of files under transpiler/_base (the kit parses exactly this grammar; no other token
# may be added). The number of registered backends the check compared is the BACKENDS line of
# <res dir>/drift.out; a check with no backends is a fault, not a pass. Exit status: 0 when the
# line reads 0, 1 when it reads
# 1 (drift), 2 when the check could not run (no rc.txt exists then: the script deletes the
# three output files of an earlier run right after its argument check). Status 0 or 1 is
# trusted only when the last line of drift.out is "RESULT <status>", which the Python side
# prints after check_drift() has returned; without it the status is 2.

RES=${1:-}
if [ -z "$RES" ] || [ ! -d "$RES" ] || [ "$#" -ne 1 ]; then
  echo "usage: check_agentic_plugins_drift.sh <res dir>" >&2
  exit 2
fi

# Every exit 2 below leaves no rc.txt, drift.out or drift.err from an earlier run in <res dir>.
rm -f "${RES:?}/rc.txt" "${RES:?}/drift.out" "${RES:?}/drift.err" "${RES:?}/.git-status.err"
gs_err=$RES/.git-status.err

TREE=$(readlink -f .)
TD=$TREE/ash-agent-plugins/agentic-coding/transpiler
PY=$TREE/.venv/bin/python

if [ ! -f "$TD/_base/manifest.json" ]; then
  echo "FAULT: $TD/_base/manifest.json is missing; the working directory is not the tree root" >&2
  exit 2
fi
if [ ! -x "$PY" ]; then
  echo "FAULT: $PY is missing; the virtual environment was not created" >&2
  exit 2
fi
if [ ! -e "$TREE/.git" ]; then
  # orchestrator.find_repository_root() walks up to a .git entry.
  echo "FAULT: no .git entry at the tree root" >&2
  exit 2
fi

# Read-only, and it runs before anything is built: the comparison reads the disk, so the
# output paths must hold exactly what is committed. git stderr stays out of the capture:
# a warning with exit 0 (an unreadable core.excludesFile is enough, and common in
# sandboxed HOMEs) would otherwise land in the dirty listing and fault every run there
# with the wrong cause named. The dirty test reads stdout only; stderr is printed only
# when git itself fails.
if ! dirty=$(git --no-optional-locks -C "$TREE" status --porcelain --ignored -- \
  ash-agent-plugins/agentic-coding/plugins skills 2>"$gs_err"); then
  echo "FAULT: git status failed in $TREE: $(cat "$gs_err")" >&2
  rm -f "${gs_err:?}"
  exit 2
fi
rm -f "${gs_err:?}"
if [ -n "$dirty" ]; then
  echo "FAULT: the output paths differ from the commit, and the check compares the disk:" >&2
  printf '%s\n' "$dirty" | head -n 20 >&2
  exit 2
fi

# The inputs too: check_drift() renders from the transpiler directory on disk, so what it
# builds matches the commit only when that directory does. No --ignored here (see the
# header): ignored files under the transpiler are not render inputs.
if ! dirty=$(git --no-optional-locks -C "$TREE" status --porcelain -- \
  ash-agent-plugins/agentic-coding/transpiler 2>"$gs_err"); then
  echo "FAULT: git status failed in $TREE: $(cat "$gs_err")" >&2
  rm -f "${gs_err:?}"
  exit 2
fi
rm -f "${gs_err:?}"
if [ -n "$dirty" ]; then
  echo "FAULT: the transpiler inputs differ from the commit, and the check renders from the disk:" >&2
  printf '%s\n' "$dirty" | head -n 20 >&2
  exit 2
fi

SNIPPET='
import sys
import traceback
from pathlib import Path

td = Path(sys.argv[1])
# The packages that decide the rendered bytes: the template engine, its escaping helper and
# the YAML dumper that three backends use.
RENDER_PATH = ("jinja2", "markupsafe", "pyyaml")


def render_path_problems():
    """Print the installed versions and the uv.lock pins; return one line per difference."""
    # These imports run inside the try below, so a module this interpreter does not carry
    # is a traceback and a FAULT line in drift.err with exit status 2, never an empty
    # drift.out the shell blames on the wrong cause. tomllib arrived in Python 3.11 and
    # ASH supports 3.10, where tomli is the same parser under its backport name. Only
    # sys, traceback and pathlib stay at the top: the except handler itself needs them,
    # and an interpreter that cannot import those cannot report anything either way.
    import importlib.metadata
    import platform
    import re

    try:
        import tomllib
    except ImportError:
        import tomli as tomllib

    # Only the render-path entries are read: uv leaves version out of some source-tree
    # entries (a root project with a dynamic version), which must not fault the check,
    # and an environment-forked resolution can hold one name at two versions, where a
    # last-entry-wins dict could compare a pin CI never installs. One name, one pin, or
    # the comparison refuses with the ambiguity named.
    locked = {}
    with open(td / "uv.lock", "rb") as fh:
        for p in tomllib.load(fh)["package"]:
            name = re.sub(r"[-_.]+", "-", p.get("name", "")).lower()
            if name not in RENDER_PATH:
                continue
            version = p.get("version")
            if version is None:
                continue
            if name in locked and locked[name] != version:
                raise RuntimeError(
                    "transpiler/uv.lock pins " + name + " at both " + locked[name]
                    + " and " + version + "; the render-path comparison needs one pin"
                )
            locked[name] = version
    installed = {n: importlib.metadata.version(n) for n in RENDER_PATH}
    pins = {n: locked.get(n, "unpinned") for n in RENDER_PATH}
    print("VERSIONS", "python=" + platform.python_version(), flush=True)
    print("INSTALLED", *(n + "=" + installed[n] for n in RENDER_PATH), flush=True)
    print("PINS", *(n + "=" + pins[n] for n in RENDER_PATH), flush=True)
    return [
        n + " installed " + installed[n] + ", pinned " + pins[n]
        for n in RENDER_PATH
        if installed[n] != pins[n]
    ]


try:
    sys.path.insert(0, str(td))
    from transpiler import orchestrator
    from transpiler.registry import BackendRegistry

    nfiles = sum(1 for p in (td / "_base").rglob("*") if p.is_file())
    print("FILES", nfiles, flush=True)
    problems = render_path_problems()
    if problems:
        raise RuntimeError(
            "render-path dependencies differ from transpiler/uv.lock: " + "; ".join(problems)
        )
    nbackends = len(BackendRegistry.names())
    print("BACKENDS", nbackends, flush=True)
    if nbackends == 0:
        raise RuntimeError("no backends are registered, so only AGENTS.md would be compared")
    drift = orchestrator.check_drift()
except Exception as exc:
    traceback.print_exc()
    print("FAULT", type(exc).__name__, exc, file=sys.stderr)
    sys.exit(2)
# The closing line is the proof that check_drift() returned. A SystemExit raised inside the
# build is not an Exception, so it passes the handler above with exit status 1 and no
# closing line; the shell below reads that as a fault, not as drift.
code = 0 if drift == 0 else 1
print("RESULT", code, flush=True)
sys.exit(code)
'

"$PY" -I -B -c "$SNIPPET" "$TD" >"$RES/drift.out" 2>"$RES/drift.err"
rc=$?

if [ "$rc" -ne 0 ] && [ "$rc" -ne 1 ]; then
  echo "FAULT: the drift check exited $rc; see drift.err in the res dir" >&2
  exit 2
fi

tag=
nfiles=
read -r tag nfiles <"$RES/drift.out"
if [ "$tag" != FILES ]; then
  echo "FAULT: the first line of drift.out is not a FILES line (empty, or printed by the transpiler)" >&2
  exit 2
fi
case $nfiles in
  '' | *[!0-9]*)
    echo "FAULT: the drift check printed no file count" >&2
    exit 2
    ;;
esac
if [ "$nfiles" -eq 0 ]; then
  echo "FAULT: the drift check saw no _base files" >&2
  exit 2
fi

# "BACKENDS <n>" is the number of backends the check compared, looked up by its tag: the
# print order of the diagnostic lines has changed before, and a positional read turns any
# extra diagnostic print into a false fault. That the count is positive is enforced by
# the Python side before RESULT can print; this read checks the line reached drift.out
# in the shape its consumers parse.
nbackends=$(awk '$1 == "BACKENDS" { print $2; exit }' "$RES/drift.out")
case $nbackends in
  '' | *[!0-9]*)
    echo "FAULT: drift.out has no BACKENDS line with a count" >&2
    exit 2
    ;;
esac

last=$(tail -n 1 "$RES/drift.out")
if [ "$last" != "RESULT $rc" ]; then
  echo "FAULT: drift.out does not end with 'RESULT $rc'; the comparison did not finish" >&2
  exit 2
fi

printf 'agentic-plugins-drift %s files=%s\n' "$rc" "$nfiles" >"$RES/rc.txt"
exit "$rc"
