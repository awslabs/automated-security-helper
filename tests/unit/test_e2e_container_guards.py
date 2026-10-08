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
which drops comments, and a call has to be a whole command at the top level of the
code path that runs (not commented out, not under an if, not behind `false &&`).
"""

from __future__ import annotations

import importlib.util
import json
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
# continuation lines joined, four spaces per nesting level). A scope is "" for the top
# level of the script or the name of a function the top level calls. The lines are in
# the order the script runs them; `after` is a line that has to come first, because an
# alias check run before the install or the image build checks nothing.
_SELF_TEST = 'bash "$REPO/scripts/e2e/alias_check.sh" self-test "$ALIAS_ASSERT";'
_ALIAS_CALLS = {
    "scripts/e2e/container.sh": [
        ("", None, _SELF_TEST),
        (
            "",
            'provenance "$TAG_FRESH" "$SRC_HEAD" fresh ||',
            (
                '"$OCI" run --rm --network none'
                ' -v "$REPO/scripts/e2e/alias_check.sh:/tmp/ash-alias/alias_check.sh:ro"'
                ' -v "$ALIAS_ASSERT:/tmp/ash-alias/assert-deprecated-alias.sh:ro"'
                ' "$TAG_FRESH" bash /tmp/ash-alias/alias_check.sh check'
                " /tmp/ash-alias/assert-deprecated-alias.sh || fail "
            ),
        ),
    ],
    "scripts/e2e/homebrew.sh": [
        ("", None, _SELF_TEST),
        (
            "leg_fresh",
            "brew install --verbose --build-from-source --formula",
            (
                'PATH="$BREW_BIN:$PATH" bash "$REPO/scripts/e2e/alias_check.sh" check'
                ' "$ALIAS_ASSERT" || fail '
            ),
        ),
    ],
}
_ALIAS_ASSERT_LINE = (
    'ALIAS_ASSERT="$REPO/.github/actions/validate-install/assert-deprecated-alias.sh";'
)


def _parse(text: str) -> list:
    """The script as bash parses it, wrapped in a function so nothing runs."""
    done = subprocess.run(
        ["bash", "-c", 'eval "__e2e() {\n$1\n}" && declare -f __e2e', "_", text],
        capture_output=True,
        text=True,
        check=False,
    )
    assert done.returncode == 0, done.stderr
    return done.stdout.splitlines()


def _scope(lines: list, name: str) -> list:
    """The commands at the top level of the script, or of one function in it."""
    if not name:
        return [
            line[4:] for line in lines if line.startswith("    ") and line[4] != " "
        ]
    start = lines.index(f"    function {name} () ")
    assert lines[start + 1] == "    { ", lines[start + 1]
    body = []
    for line in lines[start + 2 :]:
        if line == "    }" or line == "    };":
            return body
        if line.startswith("        ") and line[8] != " ":
            body.append(line[8:])
    raise AssertionError(f"{name} has no end")


def _alias_call_problems(rel: str, text: str) -> list:
    lines = _parse(text)
    top = _scope(lines, "")
    problems = []
    if _ALIAS_ASSERT_LINE not in top:
        problems.append("ALIAS_ASSERT is not set to the validate-install assert script")
    for scope, after, call in _ALIAS_CALLS[rel]:
        commands = top if not scope else _scope(lines, scope)
        at = [i for i, line in enumerate(commands) if line.startswith(call)]
        if not at:
            problems.append(f"{scope or 'top level'}: no command starting {call!r}")
            continue
        if after is not None:
            first = [i for i, line in enumerate(commands) if line.startswith(after)]
            if not first or first[0] > at[0]:
                problems.append(
                    f"{scope or 'top level'}: {call!r} runs before {after!r}"
                )
        if scope:
            # The function has to be what the top level dispatches to.
            leg = scope.removeprefix("leg_")
            if top[-1] != '"leg_$LEG"' or not any(
                line.startswith("case ") for line in top
            ):
                problems.append(f"the top level does not dispatch to {scope}")
            if f"{leg} | " not in text and f"| {leg} " not in text:
                problems.append(f"the usage check does not accept the {leg} leg")
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
    planted.write_text("".join(lines), encoding="utf-8")
    done = subprocess.run(
        [
            "bash",
            str(REPO_ROOT / "scripts" / "e2e" / "alias_check.sh"),
            "self-test",
            str(planted),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert done.returncode == 0, done.stdout + done.stderr
    assert done.stdout.count("   OK: ") == 6, done.stdout
