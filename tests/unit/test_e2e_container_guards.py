# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The checks the container e2e channel relies on, run without docker.

scripts/e2e/container.sh needs docker and a long image build, so it only runs in CI.
The two judgments it makes that are not assert_outcome's are tested here instead:
.github/scripts/assert-no-image-publish.py (nothing CI runs may push an image) and
scripts/e2e/image_provenance.py (an image carries a given tree's code). Each is shown
rejecting what it exists to reject, and the publish census is run on this tree.

The deprecated `ash` alias check (scripts/e2e/alias_check.sh) only shows up in a CI
log, so a deleted call would pass unnoticed. The last tests hold container.sh and
homebrew.sh to calling it where it runs: bash parses each script without running it,
which drops comments, and heredoc bodies are dropped after it. A call has to be a whole
command at the top level of the script or of the leg function the top level dispatches
to (not commented out, not under an if, not behind `false &&`), under `set -euo
pipefail`. Ahead of it, at any depth or in a function called there (transitively),
there may be no `set +e` and no exit or return that could end the leg green: a bare
one, status 0, or a variable status. A nonzero literal status is a failure path and is
allowed. Calls made inside `$(...)` or quoted text are not followed. On Windows the
parse runs in Git for Windows' bash, since `bash` on a runner's PATH is the WSL stub.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None, path
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


publish = _load(
    REPO_ROOT / ".github" / "scripts" / "assert-no-image-publish.py",
    "ash_assert_no_image_publish",
)
provenance = _load(
    REPO_ROOT / "scripts" / "e2e" / "image_provenance.py", "ash_e2e_image_provenance"
)


def test_publish_guard_self_test_passes(capsys):
    assert publish.self_test() == 0
    assert "SELF-TEST PASS" in capsys.readouterr().out


def test_publish_guard_passes_on_this_tree(capsys):
    files = publish.tracked_files(REPO_ROOT)
    assert publish.check(REPO_ROOT, files, publish.EXEMPT) == 0, capsys.readouterr().out


def test_publish_guard_reads_the_container_channel():
    files = publish.tracked_files(REPO_ROOT)
    for required in publish.REQUIRED:
        assert required in files


@pytest.mark.parametrize(
    "line",
    [
        "        run: docker push ghcr.io/example/ash:latest",
        "          push: true",
        "      - uses: docker/login-action@0123456789abcdef0123456789abcdef01234567 # v3",
        "  sudo nerdctl push example/ash",
        "  docker buildx build -t example/ash --push .",
        '"$OCI" push "$TAG_FRESH"',
        "$OCI image push example/ash",
        '"${RUNNER}" login ghcr.io',
        "  --push \\",
        "docker manifest push ghcr.io/example/ash",
        "docker buildx imagetools create -t ghcr.io/example/ash:1 example/ash:1",
    ],
)
def test_publish_guard_fails_a_planted_push(tmp_path, capsys, line):
    rel = "scripts/e2e/planted.sh"
    (tmp_path / "scripts" / "e2e").mkdir(parents=True)
    (tmp_path / rel).write_text(f"{line}\n", encoding="utf-8")
    assert publish.check(tmp_path, [rel], {}) == 1
    assert "planted.sh:1" in capsys.readouterr().out


def test_publish_guard_ignores_comments(tmp_path):
    rel = "scripts/e2e/commented.sh"
    (tmp_path / "scripts" / "e2e").mkdir(parents=True)
    (tmp_path / rel).write_text("# never docker push this image\n", encoding="utf-8")
    hits, stale, read = publish.scan(tmp_path, [rel], {})
    assert (hits, stale, read) == ([], [], 1)


def test_publish_guard_fails_a_stale_exemption(tmp_path, capsys):
    rel = "scripts/e2e/clean.sh"
    (tmp_path / "scripts" / "e2e").mkdir(parents=True)
    (tmp_path / rel).write_text("docker build .\n", encoding="utf-8")
    exempt = {(rel, "push: true"): "matches nothing"}
    assert publish.check(tmp_path, [rel], exempt) == 1
    assert "exemption matches no line" in capsys.readouterr().out


def test_publish_guard_excludes_deploy_but_covers_ci_roots():
    assert publish.in_scope(".github/workflows/ash-e2e.yml")
    assert publish.in_scope("scripts/e2e/container.sh")
    assert publish.in_scope("packaging/deb/verify-in-container.sh")
    assert not publish.in_scope("deploy/cdk/lib/ash-image-build.ts")
    assert not publish.in_scope(".github/scripts/assert-no-image-publish.py")


def test_provenance_self_test_passes(capsys):
    assert provenance.self_test() == 0
    assert "SELF-TEST PASS" in capsys.readouterr().out


def test_provenance_compare_accepts_this_tree_and_rejects_a_change(tmp_path):
    package = REPO_ROOT / "automated_security_helper"
    installed = provenance.manifest(package)
    assert installed, "the package has no *.py files"
    good = tmp_path / "good.json"
    good.write_text(json.dumps(installed), encoding="utf-8")
    assert (
        provenance.main(["compare", "--source", str(package), "--installed", str(good)])
        == 0
    )

    changed = dict(installed)
    first = min(changed)
    changed[first] = "0" * 64
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps(changed), encoding="utf-8")
    assert (
        provenance.main(["compare", "--source", str(package), "--installed", str(bad)])
        == 1
    )


def test_provenance_manifest_by_package_matches_by_directory(capsys):
    assert provenance.main(["manifest", "--package", "automated_security_helper"]) == 0
    by_package = json.loads(capsys.readouterr().out)
    import automated_security_helper

    by_dir = provenance.manifest(Path(automated_security_helper.__file__).parent)
    assert by_package == by_dir


def test_provenance_manifest_refuses_both_or_neither():
    assert provenance.main(["manifest"]) == 3
    assert provenance.main(["manifest", ".", "--package", "json"]) == 3


# What each script must run, as bash prints it back with `declare -f` (comments gone,
# continuation lines joined, four spaces per nesting level, heredoc bodies verbatim).
# A scope is "" for the top level of the script or the name of a function the top level
# dispatches to. `after` is a command that has to come first, because an alias check run
# before the install or the image build checks nothing. A call is a command that starts
# with `starts` and holds every one of `tokens`, in any order, so a benign edit (another
# docker flag, the mounts reordered) still passes.
_SELF_TEST = 'bash "$REPO/scripts/e2e/alias_check.sh" self-test "$ALIAS_ASSERT"'
_ALIAS_CALLS = {
    "scripts/e2e/container.sh": [
        ("", None, _SELF_TEST, ()),
        (
            "",
            'provenance "$TAG_FRESH" "$SRC_HEAD" fresh ||',
            '"$OCI" run ',
            (
                " --rm ",
                " --network none ",
                ' -v "$REPO/scripts/e2e/alias_check.sh:/tmp/ash-alias/alias_check.sh:ro" ',
                ' -v "$ALIAS_ASSERT:/tmp/ash-alias/assert-deprecated-alias.sh:ro" ',
                (
                    ' "$TAG_FRESH" bash /tmp/ash-alias/alias_check.sh check'
                    " /tmp/ash-alias/assert-deprecated-alias.sh || fail "
                ),
            ),
        ),
    ],
    "scripts/e2e/homebrew.sh": [
        ("", None, _SELF_TEST, ()),
        (
            "leg_fresh",
            "brew install --verbose --build-from-source --formula",
            (
                'PATH="$BREW_BIN:$PATH" bash "$REPO/scripts/e2e/alias_check.sh" check'
                ' "$ALIAS_ASSERT" || fail '
            ),
            (),
        ),
    ],
}
_ALIAS_ASSERT_LINE = (
    'ALIAS_ASSERT="$REPO/.github/actions/validate-install/assert-deprecated-alias.sh"'
)
# Where a command can start on a parsed line, once quoted text is gone.
_AT_COMMAND = r"(?:^|[;&|({]|\b(?:then|else|do)\b)\s*"
# An exit or return that can end the leg before the call. Only one with a nonzero
# literal status is a failure path (fail's `exit 1`, the usage check's `exit 3`): a bare
# one, `exit 0` or `exit $rc` could end the leg green without running the check.
_LEAVE = re.compile(_AT_COMMAND + r"(exit|return)\b[ \t]*([^\s;&|)}]*)")
# `set +e` (or +o errexit) lets a failed bare self-test line through.
_ERREXIT_OFF = re.compile(_AT_COMMAND + r"set\s+(?:\+\w*e\w*|\+o\s+errexit)\b")
_QUOTED = re.compile(r'"(?:[^"\\]|\\.)*"' + r"|'[^']*'")
_HEREDOC = re.compile(r"(?<!<)<<(-?)\s*(['\"]?)(\w+)\2")


def _bash() -> str:
    """A bash that runs scripts: on Windows, Git's, not the WSL stub on PATH.

    C:\\Windows\\System32\\bash.exe comes first on a Windows runner's PATH and exits 1
    without a WSL distribution. Git for Windows ships bash.exe next to git.
    """
    if os.name != "nt":
        found = shutil.which("bash")
        assert found, "no bash on PATH"
        return found
    git = shutil.which("git")
    if git is None:
        pytest.skip("no git on PATH, so no Git for Windows bash to parse the scripts")
    for parent in Path(git).resolve().parents:
        candidate = parent / "bin" / "bash.exe"
        if candidate.is_file():
            return str(candidate)
    pytest.skip(f"no Git for Windows bash.exe above {git}; the WSL stub cannot run")


# bash reads the script from stdin, drops every CR (Git for Windows bash keeps them in
# an eval string and in `$(cat)`, where they break the parse), and prints it back as the
# body of a function it never calls.
_DECLARE = (
    "src=$(cat); src=${src//$'\\r'/}; eval \"__e2e() {\n$src\n}\" && declare -f __e2e"
)


def _declare(data: bytes) -> subprocess.CompletedProcess:
    """Run _DECLARE on raw bytes. Bytes, not text: in text mode Windows turns each LF
    written to stdin into CRLF. stdin, not argv: a script is longer than a Windows
    command line allows."""
    return subprocess.run(
        [_bash(), "-c", _DECLARE], input=data, capture_output=True, check=False
    )


def _parse(text: str) -> list:
    """The script as bash parses it, wrapped in a function so nothing runs."""
    done = _declare(text.replace("\r\n", "\n").encode("utf-8"))
    assert done.returncode == 0, done.stderr.decode("utf-8", "replace")
    out = done.stdout.decode("utf-8").replace("\r\n", "\n")
    return _without_heredocs(out.splitlines())


def _without_heredocs(lines: list) -> list:
    """The parsed lines with every heredoc body dropped, so text inside one is no
    command."""
    kept, ends = [], []
    for line in lines:
        if ends:
            strip, word = ends[0]
            if (line.lstrip("\t") if strip else line) == word:
                ends.pop(0)
            continue
        kept.append(line)
        ends = [(m.group(1) == "-", m.group(3)) for m in _HEREDOC.finditer(line)]
    assert not ends, f"a heredoc ending {ends[0][1]} never ends"
    return kept


def _command(line: str, indent: int):
    """The command on a line `indent` spaces deep, without bash's trailing `;`."""
    if len(line) <= indent or line[:indent].strip() or line[indent] == " ":
        return None
    return line[indent:].rstrip().removesuffix(";").rstrip()


def _functions(lines: list) -> dict:
    """Each top-level function: name -> the line numbers of its body."""
    found = {}
    for start, line in enumerate(lines):
        match = re.fullmatch(r"    function (\S+) \(\) ", line)
        if not match:
            continue
        assert lines[start + 1] == "    { ", lines[start + 1]
        for end in range(start + 2, len(lines)):
            if lines[end].rstrip().removesuffix(";") == "    }":
                found[match.group(1)] = range(start + 2, end)
                break
        else:
            raise AssertionError(f"{match.group(1)} has no end")
    return found


def _numbered_scope(lines: list, name: str) -> list:
    """(line number, command) for the commands at the top level of the script, or of
    one function in it."""
    if not name:
        rows = range(len(lines))
        indent = 4
    else:
        rows = _functions(lines)[name]
        indent = 8
    pairs = ((i, _command(lines[i], indent)) for i in rows)
    return [(i, c) for i, c in pairs if c is not None]


def _scope(lines: list, name: str) -> list:
    """The commands at the top level of the script, or of one function in it."""
    return [c for _, c in _numbered_scope(lines, name)]


def _leaving(lines: list, rows, functions: dict, returns: bool) -> list:
    """What, on these lines (at any depth) or in a function they call, can end the leg
    or switch errexit off: [(line, why)]. A return only leaves when `returns` (the
    scope is a function, or the top level of a sourced file); a called function's
    return just ends that function."""
    found, seen, todo = [], set(), [(r, returns) for r in rows]
    while todo:
        row, leaves_on_return = todo.pop(0)
        code = _QUOTED.sub('""', lines[row].strip())
        for match in _LEAVE.finditer(code):
            kind, status = match.groups()
            if kind == "return" and not leaves_on_return:
                continue
            if not re.fullmatch(r"[1-9][0-9]*", status):
                found.append((lines[row].strip(), f"{kind} {status}".strip()))
        if _ERREXIT_OFF.search(code):
            found.append((lines[row].strip(), "errexit switched off"))
        for name, body in functions.items():
            if name not in seen and re.search(
                _AT_COMMAND + re.escape(name) + r"\b", code
            ):
                seen.add(name)
                todo.extend((r, False) for r in body)
    return found


def _case_arms(lines: list, word: str) -> list:
    """The patterns of the top-level `case "$<word>" in` the script checks usage with."""
    head = f'    case "${word}" in'
    starts = [i for i, line in enumerate(lines) if line.rstrip() == head]
    if len(starts) != 1:
        return []
    arms = []
    for line in lines[starts[0] + 1 :]:
        if line.rstrip().removesuffix(";") == "    esac":
            return arms
        if _command(line, 8) is not None and line.rstrip().endswith(")"):
            arms.append([p.strip() for p in line.strip()[:-1].split("|")])
    return []


def _alias_call_problems(rel: str, text: str) -> list:
    lines = _parse(text)
    top = _scope(lines, "")
    functions = _functions(lines)
    in_a_function = {row for body in functions.values() for row in body}
    problems = []
    first_call = None
    if _ALIAS_ASSERT_LINE not in top:
        problems.append("ALIAS_ASSERT is not set to the validate-install assert script")
    for scope, after, starts, tokens in _ALIAS_CALLS[rel]:
        where = scope or "top level"
        numbered = _numbered_scope(lines, scope)
        commands = [c for _, c in numbered]
        at = [
            i
            for i, c in enumerate(commands)
            if c.startswith(starts) and all(token in f"{c} " for token in tokens)
        ]
        if not at:
            problems.append(f"{where}: no command {starts!r} holding {tokens!r}")
            continue
        if not scope:
            first_call = at[0] if first_call is None else min(first_call, at[0])
        if after is not None:
            first = [i for i, c in enumerate(commands) if c.startswith(after)]
            if not first or first[0] > at[0]:
                problems.append(f"{where}: {starts!r} runs before {after!r}")
        call_row = numbered[at[0]][0]
        if scope:
            before = range(functions[scope].start, call_row)
        else:
            before = [r for r in range(call_row) if r not in in_a_function]
        for line, why in _leaving(lines, before, functions, returns=bool(scope)):
            problems.append(f"{where}: {line!r} ({why}) comes before {starts!r}")
        if scope:
            # The function has to be what the top level dispatches to, for a leg the
            # usage check lets through.
            leg = scope.removeprefix("leg_")
            if top[-1] != '"leg_$LEG"':
                problems.append(f"the top level does not dispatch to {scope}")
            if not any(
                leg in arm and "*" not in arm for arm in _case_arms(lines, "LEG")
            ):
                problems.append(f"the usage check does not accept the {leg} leg")
            # ...and nothing at the top level may leave before that dispatch.
            dispatch = _numbered_scope(lines, "")[-1][0]
            before = [r for r in range(dispatch) if r not in in_a_function]
            for line, why in _leaving(lines, before, functions, returns=False):
                problems.append(f"top level: {line!r} ({why}) comes before {scope}")
    # A bare self-test line only stops the leg when it fails under `set -e`.
    errexit = [i for i, c in enumerate(top) if c == "set -euo pipefail"]
    if not errexit or (first_call is not None and errexit[0] > first_call):
        problems.append("top level: no `set -euo pipefail` before the alias calls")
    return problems


@pytest.mark.parametrize("rel", sorted(_ALIAS_CALLS))
def test_e2e_leg_runs_the_alias_check(rel):
    text = (REPO_ROOT / rel).read_text(encoding="utf-8")
    assert _alias_call_problems(rel, text) == []


def _commands(text: str, mode: str) -> list:
    """(first, last) line numbers of each command that runs alias_check.sh in a mode,
    following backslash continuations both ways."""
    lines = text.splitlines()
    spans = []
    for i, line in enumerate(lines):
        if "alias_check.sh" not in line or line.lstrip().startswith("#"):
            continue
        first = i
        while first > 0 and lines[first - 1].rstrip().endswith("\\"):
            first -= 1
        last = i
        while lines[last].rstrip().endswith("\\"):
            last += 1
        if (
            f" {mode} " in " ".join(lines[first : last + 1])
            and (first, last) not in spans
        ):
            spans.append((first, last))
    assert spans, f"no alias_check.sh {mode} command in the script"
    return spans


def _rewrite(text: str, mode: str, edit) -> str:
    lines = text.splitlines()
    for first, last in reversed(_commands(text, mode)):
        lines[first : last + 1] = edit(lines[first : last + 1])
    return "\n".join(lines) + "\n"


def _deleted(block: list) -> list:
    return []


def _commented(block: list) -> list:
    return ["# " + line for line in block]


def _under_if_false(block: list) -> list:
    return ["if false; then", *block, "fi"]


def _behind_false(block: list) -> list:
    indent = block[0][: len(block[0]) - len(block[0].lstrip())]
    return [f"{indent}false && {block[0].lstrip()}", *block[1:]]


def _in_uncalled_function(block: list) -> list:
    return ["never_called() {", *block, "}"]


def _before_the_install(text: str, mode: str) -> str:
    # Move the check to the top of the script, ahead of the install or image build.
    spans = _commands(text, mode)
    lines = text.splitlines()
    moved = []
    for first, last in reversed(spans):
        moved[:0] = [line.lstrip() for line in lines[first : last + 1]]
        del lines[first : last + 1]
    at = next(i for i, line in enumerate(lines) if line.startswith("ALIAS_ASSERT="))
    lines[at + 1 : at + 1] = moved
    return "\n".join(lines) + "\n"


_PLANTS = {
    "deleted": _deleted,
    "commented-out": _commented,
    "under-if-false": _under_if_false,
    "behind-false": _behind_false,
    "in-an-uncalled-function": _in_uncalled_function,
}


@pytest.mark.parametrize("rel", sorted(_ALIAS_CALLS))
@pytest.mark.parametrize("mode", ["self-test", "check"])
@pytest.mark.parametrize("plant", sorted(_PLANTS))
def test_e2e_alias_guard_rejects_a_call_that_does_not_run(rel, mode, plant):
    text = (REPO_ROOT / rel).read_text(encoding="utf-8")
    planted = _rewrite(text, mode, _PLANTS[plant])
    assert planted != text
    assert _alias_call_problems(rel, planted) != []


@pytest.mark.parametrize("rel", sorted(_ALIAS_CALLS))
def test_e2e_alias_guard_rejects_a_check_before_the_install(rel):
    text = (REPO_ROOT / rel).read_text(encoding="utf-8")
    planted = _before_the_install(text, "check")
    assert planted != text
    problems = _alias_call_problems(rel, planted)
    assert problems != [], planted


# A notice as the assert script would have to write it if it ever held a double quote,
# a `$`, a backtick or a single quote. alias_check.sh copies the source text between the
# quotes into each stub's own double-quoted string, where sh undoes the same escapes bash
# does, so the stubs print the string the assert script compares against. Quoting the
# stub's notice any other way makes this test fail.
_HOSTILE_NOTICE = 'warning: \\"ash\\" costs \\$5, \\`ash\\` is it\'s gone; use ashx.'


def test_alias_check_self_test_survives_a_notice_with_shell_characters(tmp_path):
    assert_script = (
        REPO_ROOT
        / ".github"
        / "actions"
        / "validate-install"
        / "assert-deprecated-alias.sh"
    )
    text = assert_script.read_text(encoding="utf-8")
    lines = text.splitlines(keepends=True)
    at = [i for i, line in enumerate(lines) if line.startswith("NOTICE=")]
    assert len(at) == 1, "the assert script has no single NOTICE= line"
    lines[at[0]] = f'NOTICE="{_HOSTILE_NOTICE}"\n'
    planted = tmp_path / "assert-deprecated-alias.sh"
    planted.write_bytes("".join(lines).replace("\r\n", "\n").encode("utf-8"))
    done = subprocess.run(
        [
            _bash(),
            (REPO_ROOT / "scripts" / "e2e" / "alias_check.sh").as_posix(),
            "self-test",
            planted.as_posix(),
        ],
        capture_output=True,
        check=False,
    )
    out = done.stdout.decode("utf-8", "replace").replace("\r\n", "\n")
    err = done.stderr.decode("utf-8", "replace")
    assert done.returncode == 0, out + err
    assert out.count("   OK: ") == 6, out


def _top_level_exit_before_the_check(text: str) -> str:
    # container.sh: the check is a top-level command; homebrew.sh: an exit before the
    # dispatch to leg_fresh.
    anchor = (
        "ALIAS_ASSERT="
        if "leg_$LEG" in text
        else 'say "the image\'s deprecated ash alias"'
    )
    lines = text.splitlines()
    at = next(i for i, line in enumerate(lines) if line.startswith(anchor))
    lines.insert(at + 1, "exit 0")
    return "\n".join(lines) + "\n"


def _conditional_exit_before_the_check(text: str) -> str:
    lines = text.splitlines()
    at = next(i for i, line in enumerate(lines) if line.startswith("ALIAS_ASSERT="))
    lines.insert(at + 1, '[ -n "$ALIAS_ASSERT" ] && exit 0')
    return "\n".join(lines) + "\n"


def _return_in_leg_fresh(text: str) -> str:
    old = '  brew test --verbose "$FORMULA"\n'
    assert old in text
    return text.replace(old, old + "  return 0\n", 1)


def _errexit_removed(text: str) -> str:
    assert "\nset -euo pipefail\n" in text
    return text.replace("\nset -euo pipefail\n", "\nset -u\n", 1)


def _call_only_in_a_heredoc(text: str, mode: str, indent: int) -> str:
    # bash prints a heredoc body verbatim, so the call joined onto one line and indented
    # like a command at its depth would read as one if heredocs were not dropped.
    pad = " " * indent
    return _rewrite(
        text,
        mode,
        lambda block: [
            "cat >/dev/null <<'SH'",
            pad + " ".join(line.strip().removesuffix("\\").strip() for line in block),
            "SH",
        ],
    )


def _usage_only_in_a_comment(text: str) -> str:
    old = "  fresh | upgrade | negative) ;;"
    assert old in text
    return text.replace(old, "  upgrade | negative) ;;  # fresh | is gone", 1)


_SCRIPT_PLANTS = [
    ("scripts/e2e/container.sh", _top_level_exit_before_the_check),
    ("scripts/e2e/homebrew.sh", _top_level_exit_before_the_check),
    ("scripts/e2e/container.sh", _conditional_exit_before_the_check),
    ("scripts/e2e/homebrew.sh", _conditional_exit_before_the_check),
    ("scripts/e2e/homebrew.sh", _return_in_leg_fresh),
    ("scripts/e2e/container.sh", _errexit_removed),
    ("scripts/e2e/homebrew.sh", _errexit_removed),
    ("scripts/e2e/container.sh", lambda t: _call_only_in_a_heredoc(t, "check", 4)),
    ("scripts/e2e/homebrew.sh", lambda t: _call_only_in_a_heredoc(t, "check", 8)),
    ("scripts/e2e/container.sh", lambda t: _call_only_in_a_heredoc(t, "self-test", 4)),
    ("scripts/e2e/homebrew.sh", _usage_only_in_a_comment),
]


@pytest.mark.parametrize(
    ("rel", "plant"),
    _SCRIPT_PLANTS,
    ids=[
        "container-exit",
        "homebrew-exit",
        "container-and-exit",
        "homebrew-and-exit",
        "homebrew-return",
        "container-no-errexit",
        "homebrew-no-errexit",
        "container-check-in-heredoc",
        "homebrew-check-in-heredoc",
        "container-self-test-in-heredoc",
        "homebrew-usage-in-comment",
    ],
)
def test_e2e_alias_guard_rejects_a_script_that_skips_the_call(rel, plant):
    text = (REPO_ROOT / rel).read_text(encoding="utf-8")
    planted = plant(text)
    assert planted != text
    assert _alias_call_problems(rel, planted) != []


def test_e2e_alias_guard_accepts_a_benign_edit_to_the_container_call():
    rel = "scripts/e2e/container.sh"
    text = (REPO_ROOT / rel).read_text(encoding="utf-8")
    mounts = (
        '  -v "$REPO/scripts/e2e/alias_check.sh:/tmp/ash-alias/alias_check.sh:ro" \\\n'
        '  -v "$ALIAS_ASSERT:/tmp/ash-alias/assert-deprecated-alias.sh:ro" \\\n'
    )
    assert mounts in text
    swapped = "".join(reversed(mounts.splitlines(keepends=True)))
    edited = text.replace(mounts, "  --cpus 1 \\\n" + swapped, 1)
    assert edited != text
    assert _alias_call_problems(rel, edited) == []


def test_e2e_alias_guard_reads_crlf_like_lf():
    rel = "scripts/e2e/homebrew.sh"
    text = (REPO_ROOT / rel).read_text(encoding="utf-8")
    assert _alias_call_problems(rel, text.replace("\n", "\r\n")) == []


def test_bash_on_windows_is_gits_not_the_wsl_stub(tmp_path, monkeypatch):
    # A Windows runner's PATH finds C:\Windows\System32\bash.exe (the WSL stub) for
    # `bash`; the guard has to take the bash.exe Git for Windows ships next to git.
    git_root = tmp_path / "Git"
    (git_root / "cmd").mkdir(parents=True)
    (git_root / "bin").mkdir()
    (git_root / "cmd" / "git.exe").write_bytes(b"")
    (git_root / "bin" / "bash.exe").write_bytes(b"")
    stub = tmp_path / "System32" / "bash.exe"
    found = {"git": str(git_root / "cmd" / "git.exe"), "bash": str(stub)}
    monkeypatch.setattr(shutil, "which", lambda name: found.get(name))
    monkeypatch.setattr(sys.modules[__name__], "os", type("nt", (), {"name": "nt"}))
    assert _bash() == str((git_root / "bin" / "bash.exe").resolve())

    found.pop("git")
    with pytest.raises(pytest.skip.Exception, match="no git on PATH"):
        _bash()


def _insert_after_alias_assert(text: str, *new: str) -> str:
    # Right after ALIAS_ASSERT= is ahead of every alias call and of the leg dispatch.
    lines = text.splitlines()
    at = next(i for i, line in enumerate(lines) if line.startswith("ALIAS_ASSERT="))
    lines[at + 1 : at + 1] = list(new)
    return "\n".join(lines) + "\n"


_NESTED_LEAVES = {
    "if-exit": ("if true; then", "  exit 0", "fi"),
    "group-exit": ("{ exit 0; }",),
    "function-that-exits": ("skip_all() { exit 0; }", "skip_all"),
    "function-calling-one-that-exits": (
        "skip_all() { exit; }",
        "skip_some() { skip_all; }",
        "skip_some",
    ),
    "or-exit-0": ("true || exit 0",),
    "exit-a-variable": ('rc=0; [ -n "$REPO" ] || exit "$rc"',),
    "set-plus-e": ("set +e",),
    "set-plus-o-errexit": ("set +o errexit",),
}


@pytest.mark.parametrize("rel", sorted(_ALIAS_CALLS))
@pytest.mark.parametrize("plant", sorted(_NESTED_LEAVES))
def test_e2e_alias_guard_rejects_a_nested_exit_before_the_call(rel, plant):
    text = (REPO_ROOT / rel).read_text(encoding="utf-8")
    planted = _insert_after_alias_assert(text, *_NESTED_LEAVES[plant])
    assert _alias_call_problems(rel, planted) != []


def test_e2e_alias_guard_rejects_a_nested_return_in_leg_fresh():
    rel = "scripts/e2e/homebrew.sh"
    text = (REPO_ROOT / rel).read_text(encoding="utf-8")
    old = '  brew test --verbose "$FORMULA"\n'
    assert old in text
    planted = text.replace(old, old + "  if true; then return; fi\n", 1)
    assert _alias_call_problems(rel, planted) != []


@pytest.mark.parametrize("rel", sorted(_ALIAS_CALLS))
def test_e2e_alias_guard_accepts_failure_paths_and_uncalled_exits(rel):
    # A nonzero exit fails the leg loudly, an exit in a function nothing calls never
    # runs, and a called function's return only ends that function.
    text = (REPO_ROOT / rel).read_text(encoding="utf-8")
    edited = _insert_after_alias_assert(
        text,
        '[ -f "$ALIAS_ASSERT" ] || { printf "no assert\\n" >&2; exit 1; }',
        "never_called() { exit 0; }",
        "done_early() { return 0; }",
        "done_early",
    )
    assert _alias_call_problems(rel, edited) == []


@pytest.mark.parametrize("rel", sorted(_ALIAS_CALLS))
def test_bash_parses_a_crlf_script_from_raw_bytes(rel):
    # What a Windows checkout or a text-mode pipe hands bash: CRLF bytes on stdin. The
    # shell side has to drop the CRs itself and print what the LF script gives.
    text = (REPO_ROOT / rel).read_text(encoding="utf-8")
    lf = _declare(text.encode("utf-8"))
    crlf = _declare(text.replace("\n", "\r\n").encode("utf-8"))
    assert lf.returncode == 0, lf.stderr
    assert crlf.returncode == 0, crlf.stderr
    assert crlf.stdout == lf.stdout
