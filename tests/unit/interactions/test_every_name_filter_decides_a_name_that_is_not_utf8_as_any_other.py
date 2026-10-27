# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every filter that decides by file name decides a name that is not UTF-8 as any other.

A file whose name is not valid UTF-8 (latin-1 ``secr\\xe9t.py``) sits beside an
ASCII-named control (``secret.py``) holding the same secret. Each cell points one name
filter at both files and runs ``ash scan`` in a child, as a user runs it, then reads
the results file: the file named so gets the decision the control gets. The filters:

- an ignore path in the repository's own config, written with the byte itself (a
  YAML escape), as the report shows the name (``\\udcNN``) and as a glob;
- an ignore path in the operator's config file and in ``--config-overrides``;
- a suppression by path;
- an inline ``ash-ignore`` comment;
- an ``.ignore`` and a ``.gitignore`` line holding the byte;
- ``--changed-files-only``, with both files changed and with neither changed.

Each cell also checks that the filter decided something, so a filter that ignored
both files' names would fail here rather than pass by leaving both alone. The
driver is the one in test_a_name_that_is_not_utf8_keeps_the_results_file.py: every
tool probe is answered as on a host without the tool, and every program start but
ASH's detect-secrets worker, and ``git`` in the cells that need it, is refused.
"""

from __future__ import annotations

import os
import subprocess  # nosec B404 - git builds the fixture repositories
from pathlib import Path
from typing import Dict, List, Tuple

import pytest

from tests.unit.interactions import (
    test_a_name_that_is_not_utf8_keeps_the_results_file as base,
)

#: The file whose name is not UTF-8, and the control.
ODD = base._ODD
PLAIN = base._PLAIN
SECRET = base._SECRET
#: The two names as the results file writes them.
ODD_RECORDED = base._ODD_RECORDED
PLAIN_RECORDED = "secret.py"

#: A rule detect-secrets reports for the secret line, for the inline comment.
RULE = "SECRET-SECRET-KEYWORD"


def _decisions(output: Path) -> Dict[str, List[Tuple[str, bool]]]:
    """(rule, suppressed) of each finding in *output*'s results file, by file name."""
    import json

    with open(output / "ash_aggregated_results.json", "rb") as handle:
        results = json.loads(handle.read().decode("utf-8"))
    found: Dict[str, List[Tuple[str, bool]]] = {ODD_RECORDED: [], PLAIN_RECORDED: []}
    for run in (results.get("sarif") or {}).get("runs") or []:
        for result in run.get("results") or []:
            uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            name = os.path.basename(uri)
            if name in found:
                found[name].append(
                    (result.get("ruleId", ""), bool(result.get("suppressions")))
                )
    return {name: sorted(rules) for name, rules in found.items()}


def _scan(
    tmp_path: Path, source: Path, *extra, allow_program: str | None = None
) -> Dict[str, List[Tuple[str, bool]]]:
    code, said, output, started = base._scan(
        tmp_path, source, *extra, allow_program=allow_program
    )
    assert code in (0, 2), said
    assert "Traceback" not in said, said
    assert started == [], started
    return _decisions(output)


#: A file no filter names, so a run whose filters leave out both files has a file
#: left to scan: with none, a scan exits 1 to say it showed nothing.
KEEP = {b"keep.py": b"x = 1\n"}


def _tree(tmp_path: Path, name: str, extra: Dict[bytes, bytes]) -> Path:
    files = {PLAIN: SECRET, ODD: SECRET, **KEEP}
    files.update(extra)
    return base._tree(tmp_path / name, files)


def _yaml_config(section: str, *entries: bytes) -> Dict[bytes, bytes]:
    body = b"".join(
        b"    - path: " + entry + b'\n      reason: "x"\n' for entry in entries
    )
    return {
        b".ash/.ash.yaml": b"global_settings:\n  " + section.encode() + b":\n" + body
    }


@pytest.fixture(scope="module")
def unfiltered(tmp_path_factory) -> Dict[str, List[Tuple[str, bool]]]:
    """Both files with no filter: the same findings, none suppressed."""
    tmp_path = tmp_path_factory.mktemp("unfiltered")
    decisions = _scan(tmp_path, _tree(tmp_path, "unfiltered", {}))
    assert decisions[PLAIN_RECORDED], decisions
    assert decisions[ODD_RECORDED] == decisions[PLAIN_RECORDED], decisions
    return decisions


#: Ignore paths, as the repository's own config writes them.
_IGNORED_BY_CONFIG = {
    "yaml-escape": _yaml_config("ignore_paths", b'"secr\\udce9t.py"', b'"secret.py"'),
    "as-the-report-shows-it": _yaml_config(
        "ignore_paths", b"'secr\\udce9t.py'", b"'secret.py'"
    ),
    "glob": _yaml_config("ignore_paths", b"'secr*t.py'"),
    # ? for the one byte, which matches the control's "e" too.
    "glob-one-character": _yaml_config("ignore_paths", b"'secr?t.py'"),
    "ignore-file": {b".ignore": ODD + b"\n" + PLAIN + b"\n"},
    "gitignore": {b".gitignore": ODD + b"\n" + PLAIN + b"\n"},
}


@pytest.mark.parametrize("shape", sorted(_IGNORED_BY_CONFIG))
def test_a_file_named_so_is_ignored_as_the_control_is(tmp_path, unfiltered, shape):
    decisions = _scan(tmp_path, _tree(tmp_path, shape, _IGNORED_BY_CONFIG[shape]))

    assert decisions[PLAIN_RECORDED] == [], decisions
    assert decisions[ODD_RECORDED] == decisions[PLAIN_RECORDED], decisions


def test_an_operator_config_ignores_a_file_named_so_as_the_control(
    tmp_path, unfiltered
):
    config = tmp_path / "operator.yaml"
    config.write_bytes(
        _yaml_config("ignore_paths", b'"secr\\udce9t.py"', b'"secret.py"')[
            b".ash/.ash.yaml"
        ]
    )

    decisions = _scan(
        tmp_path, _tree(tmp_path, "operator", {}), "--config", str(config)
    )

    assert decisions[PLAIN_RECORDED] == [], decisions
    assert decisions[ODD_RECORDED] == decisions[PLAIN_RECORDED], decisions


def test_a_config_override_ignores_a_file_named_so_as_the_control(tmp_path, unfiltered):
    override = (
        b'global_settings.ignore_paths+=[{"path": "'
        + ODD
        + b'", "reason": "x"}, {"path": "secret.py", "reason": "x"}]'
    )

    decisions = _scan(
        tmp_path,
        _tree(tmp_path, "override", {}),
        "--config-overrides",
        os.fsdecode(override),
    )

    assert decisions[PLAIN_RECORDED] == [], decisions
    assert decisions[ODD_RECORDED] == decisions[PLAIN_RECORDED], decisions


def test_a_suppression_by_path_suppresses_a_file_named_so_as_the_control(
    tmp_path, unfiltered
):
    config = _yaml_config("suppressions", b'"secr\\udce9t.py"', b'"secret.py"')

    decisions = _scan(tmp_path, _tree(tmp_path, "suppressed", config))

    assert decisions[PLAIN_RECORDED], decisions
    assert all(suppressed for _rule, suppressed in decisions[PLAIN_RECORDED])
    assert decisions[ODD_RECORDED] == decisions[PLAIN_RECORDED], decisions


def test_an_inline_comment_suppresses_in_a_file_named_so_as_in_the_control(
    tmp_path, unfiltered
):
    commented = SECRET.replace(
        b'EXAMPLEKEY"\n', b'EXAMPLEKEY"  # ash-ignore: ' + RULE.encode() + b" x\n"
    )
    assert commented != SECRET
    source = base._tree(tmp_path / "inline", {PLAIN: commented, ODD: commented, **KEEP})

    decisions = _scan(tmp_path, source)

    assert (RULE, True) in decisions[PLAIN_RECORDED], decisions
    assert decisions[ODD_RECORDED] == decisions[PLAIN_RECORDED], decisions


def _git(source: Path, *args: str) -> str:
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(source.parent),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@example.com",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@example.com",
    }
    done = subprocess.run(  # nosec B603 B607 - git on a fixture repository
        ["git", *args], cwd=source, env=env, capture_output=True, check=True
    )
    return done.stdout.decode("utf-8").strip()


def _repository(tmp_path: Path, name: str, base_files: Dict[bytes, bytes]) -> Path:
    source = base._tree(tmp_path / name, {b"other.py": b"x = 1\n", **base_files})
    _git(source, "init", "-q")
    _git(source, "add", "-A")
    _git(source, "commit", "-q", "-m", "base")
    return source


def _changed_only(tmp_path: Path, source: Path, base_ref: str):
    # The child starts git, which --changed-files-only asks for the changed names.
    return _scan(
        tmp_path,
        source,
        "--changed-files-only",
        "--base-ref",
        base_ref,
        allow_program="git",
    )


def test_changed_files_only_keeps_a_changed_file_named_so_as_the_control(
    tmp_path, unfiltered
):
    source = _repository(tmp_path, "both-changed", {})
    base_ref = _git(source, "rev-parse", "HEAD")
    for name in (PLAIN, ODD):
        with open(os.path.join(os.fsencode(source), name), "wb") as handle:
            handle.write(SECRET)
    _git(source, "add", "-A")
    _git(source, "commit", "-q", "-m", "both")

    decisions = _changed_only(tmp_path, source, base_ref)

    assert decisions[PLAIN_RECORDED], decisions
    assert decisions[ODD_RECORDED] == decisions[PLAIN_RECORDED], decisions


def test_changed_files_only_drops_an_unchanged_file_named_so_as_the_control(
    tmp_path, unfiltered
):
    source = _repository(tmp_path, "neither-changed", {PLAIN: SECRET, ODD: SECRET})
    base_ref = _git(source, "rev-parse", "HEAD")
    (source / "other.py").write_text("x = 2\n", encoding="utf-8")
    _git(source, "commit", "-q", "-am", "other")

    decisions = _changed_only(tmp_path, source, base_ref)

    assert decisions[PLAIN_RECORDED] == [], decisions
    assert decisions[ODD_RECORDED] == decisions[PLAIN_RECORDED], decisions
