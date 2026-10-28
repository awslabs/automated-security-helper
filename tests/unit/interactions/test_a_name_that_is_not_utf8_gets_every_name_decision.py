# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A file whose name is not UTF-8 gets every decision ASH makes by name, as a plain name does.

ASH decides by a file's name whether to scan it, whether to keep a finding in it, and
whether to suppress one. It reads the name from the filesystem or from git, where it
holds a lone surrogate, and from a result, which records it in the record form (the
surrogate as the six characters ``\\udcNN``). A comparison of the two forms misses
with no error, so the decision is lost for that file alone: an ignored file is scanned
and reported, a suppressed finding is shown, a changed file's findings are dropped.

Each case below makes one decision for two files at once, ``secr\\xe9t.py`` (latin-1,
not UTF-8) and ``secret.py``, beside ``keep.py``, which no decision names. One
``ash scan`` over the three must give the first file what it gives the second, and
must still report keep.py, so a case whose decision did nothing, or did too much,
fails too.

A name that is not UTF-8 is written in each place the way that place can hold it:
- in a YAML double-quoted string or a JSON string, as the escape ``\\udce9``, which
  both read as the surrogate;
- in a YAML single-quoted string, as the report shows it, the six characters;
- in an argument or an ignore file, as the byte itself.
"""

from __future__ import annotations

import io
import json
import os
import zipfile
from pathlib import Path
from typing import Callable, Dict, List, NamedTuple, Optional

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Location,
    Message,
    PhysicalLocation,
    Result,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)
from automated_security_helper.utils.scan_output_dirs import (
    drop_results_in_ash_output_dirs,
    mark_converted_results,
)
from tests.utils import undecodable_names as names
from tests.utils.undecodable_names import (
    ABSENT,
    CONTROL,
    KEEP,
    ODD_BYTES,
    RECORDED,
    REPORTED,
    SUPPRESSED,
)

# Every test here plants a file whose name is not UTF-8.
if os.name == "nt":
    pytest.skip(
        "a file name that is not UTF-8 cannot exist on NTFS (names are UTF-16)",
        allow_module_level=True,
    )

#: The rule an inline suppression names; detect-secrets reports the line under it.
INLINE_RULE = "SECRET-SECRET-KEYWORD"


class Case(NamedTuple):
    """What a case adds to the tree and the command line, and what it decides."""

    #: Files beside the three, name to content.
    files: Dict[object, bytes]
    #: Arguments after the scan's own.
    args: List[object]
    #: What the control, secret.py, gets.
    control: str
    #: What keep.py gets.
    keep: str = REPORTED
    #: The rule the decision is about, or None for every finding in the file.
    rule: Optional[str] = None
    #: A git repository the tree is committed to, with keep.py on the base branch.
    git: bool = False
    #: The URI, or the end of one, of the odd file's findings and the control's.
    odd_uri: str = RECORDED
    control_uri: str = CONTROL


def _yaml_list(key: str, entries: List[str]) -> str:
    """``global_settings.<key>`` in YAML, one entry per path as written in *entries*
    (already quoted)."""
    rows = "".join(
        f"    - path: {path}\n"
        "      rule_id: 'SECRET-*'\n"
        "      reason: decided by name\n"
        if key == "suppressions"
        else f"    - path: {path}\n      reason: decided by name\n"
        for path in entries
    )
    return f"global_settings:\n  {key}:\n{rows}"


#: The odd name in a YAML double-quoted string: the escape, read as the surrogate.
YAML_ESCAPE = '"secr\\udce9t.py"'
#: The odd name in a YAML single-quoted string: the six characters the report shows.
YAML_AS_REPORTED = "'secr\\udce9t.py'"


def _config_file(key: str, odd: str) -> Callable[[Path], Case]:
    def case(tmp_path: Path) -> Case:
        config = tmp_path / "operator.yaml"
        config.write_text(_yaml_list(key, [odd, f"'{CONTROL}'"]), encoding="utf-8")
        decided = ABSENT if key == "ignore_paths" else SUPPRESSED
        return Case(files={}, args=["--config", str(config)], control=decided)

    return case


def _override(key: str) -> Callable[[Path], Case]:
    def case(tmp_path: Path) -> Case:
        extra = ', "rule_id": "SECRET-*"' if key == "suppressions" else ""
        entries = ", ".join(
            f'{{"path": "{name}", "reason": "decided by name"{extra}}}'
            for name in ("\0", CONTROL)
        )
        # The odd name reaches argv as its byte: the child decodes it as a file name.
        value = f"global_settings.{key}+=[{entries}]".encode("utf-8")
        value = value.replace(b"\0", ODD_BYTES)
        decided = ABSENT if key == "ignore_paths" else SUPPRESSED
        return Case(files={}, args=["--config-overrides", value], control=decided)

    return case


def _repo_yaml(tmp_path: Path) -> Case:
    text = _yaml_list("ignore_paths", [YAML_ESCAPE, f"'{CONTROL}'"])
    return Case(files={".ash/.ash.yaml": text.encode("utf-8")}, args=[], control=ABSENT)


def _repo_json(tmp_path: Path) -> Case:
    document = {
        "global_settings": {
            "ignore_paths": [
                {"path": "secr\\udce9t.py", "reason": "decided by name"},
                {"path": CONTROL, "reason": "decided by name"},
            ]
        }
    }
    # json.dumps would escape the backslash; the file holds the escape itself.
    text = json.dumps(document).replace("secr\\\\udce9t.py", "secr\\udce9t.py")
    return Case(files={".ash/.ash.json": text.encode("utf-8")}, args=[], control=ABSENT)


def _inline(tmp_path: Path) -> Case:
    trailer = f"  # ash-ignore: {INLINE_RULE} reviewed"
    return Case(
        files={
            ODD_BYTES: names.secret_source(trailer=trailer),
            CONTROL: names.secret_source(trailer=trailer),
        },
        args=[],
        control=SUPPRESSED,
        rule=INLINE_RULE,
    )


def _changed_files(tmp_path: Path) -> Case:
    return Case(
        files={},
        args=["--changed-files-only", "--base-ref", "base"],
        control=REPORTED,
        keep=ABSENT,
        git=True,
    )


def _ignore_file_excludes(tmp_path: Path) -> Case:
    return Case(
        files={".gitignore": b"secret.py\n" + ODD_BYTES + b"\n"},
        args=[],
        control=ABSENT,
    )


def _ignore_file_includes(tmp_path: Path) -> Case:
    return Case(
        files={".gitignore": b"*.py\n!secret.py\n!" + ODD_BYTES + b"\n"},
        args=[],
        control=REPORTED,
        keep=ABSENT,
    )


def _zip(member: str) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr(member, names.secret_source())
    return buffer.getvalue()


def _archive(tmp_path: Path) -> Case:
    """An ignore path naming an archive: the converter does not extract it, so no
    finding comes from its member."""
    config = tmp_path / "operator.yaml"
    config.write_text(
        _yaml_list("ignore_paths", ['"secr\\udce9t.zip"', "'secret.zip'"]),
        encoding="utf-8",
    )
    return Case(
        files={
            b"secr\xe9t.zip": _zip("odd_member.py"),
            b"secret.zip": _zip("control_member.py"),
        },
        args=["--config", str(config)],
        control=ABSENT,
        odd_uri="odd_member.py",
        control_uri="control_member.py",
    )


CASES: Dict[str, Callable[[Path], Case]] = {
    "ignore-path-config-file-escape": _config_file("ignore_paths", YAML_ESCAPE),
    "ignore-path-config-file-as-reported": _config_file(
        "ignore_paths", YAML_AS_REPORTED
    ),
    "ignore-path-config-overrides": _override("ignore_paths"),
    "ignore-path-repo-yaml": _repo_yaml,
    "ignore-path-repo-json": _repo_json,
    "suppression-config-file-escape": _config_file("suppressions", YAML_ESCAPE),
    "suppression-config-file-as-reported": _config_file(
        "suppressions", YAML_AS_REPORTED
    ),
    "suppression-config-overrides": _override("suppressions"),
    "suppression-inline-comment": _inline,
    "changed-files-only": _changed_files,
    "ignore-file-excludes": _ignore_file_excludes,
    "ignore-file-includes": _ignore_file_includes,
    "ignore-path-archive": _archive,
}


def _decision(found: List[names.Finding], uri: str, rule: Optional[str]) -> str:
    """names.decision for the findings whose URI is *uri*, or ends in "/<uri>", as a
    converted member's absolute URI does."""
    return names.decision(
        [f._replace(uri=uri) if f.uri.endswith("/" + uri) else f for f in found],
        uri,
        rule,
    )


def _tree(tmp_path: Path, case: Case) -> Path:
    files: Dict[object, bytes] = {
        ODD_BYTES: names.secret_source(),
        CONTROL: names.secret_source(),
        KEEP: names.secret_source(),
    }
    files.update(case.files)
    source = tmp_path / "src"
    if not case.git:
        return names.make_tree(source, files)
    names.make_tree(source, {KEEP: files.pop(KEEP)})
    names.git(source, "init", "-q", "-b", "main")
    names.git(source, "add", "-A")
    names.git(source, "commit", "-q", "-m", "base")
    names.git(source, "branch", "base")
    names.make_tree(source, files)
    names.git(source, "add", "-A")
    names.git(source, "commit", "-q", "-m", "change")
    return source


@pytest.mark.parametrize("label", sorted(CASES))
def test_the_odd_name_gets_the_decision_the_plain_name_gets(tmp_path, label):
    case = CASES[label](tmp_path)
    source = _tree(tmp_path, case)
    output = tmp_path / "out"

    ran = names.scan(tmp_path, source, output, *case.args)

    assert names.results_file(output).is_file(), ran
    found = names.findings(output)
    got = {
        "odd": _decision(found, case.odd_uri, case.rule),
        "control": _decision(found, case.control_uri, case.rule),
        "keep": names.decision(found, KEEP),
    }
    # The control shows the decision was made; keep.py, that it was made for those
    # two files and no others.
    assert (got["control"], got["keep"]) == (case.control, case.keep), (got, ran)
    assert got["odd"] == got["control"], (got, found, ran)


# --- Decisions made inside a scan, by functions a whole scan reaches only through
# scanners that walk the tree themselves.

ODD_DIR = os.fsdecode(b"caf\xe9")
PLAIN_DIR = "cafe"


def _make(path: Path) -> Path:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("x = 1\n", encoding="utf-8")
    except (UnicodeError, OSError) as error:
        pytest.skip(f"this filesystem cannot hold a name that is not UTF-8: {error}")
    return path


def _report(*uris: str) -> SarifReport:
    return SarifReport(
        runs=[
            Run(
                tool=Tool(driver=ToolComponent(name="scripted")),
                results=[
                    Result(
                        ruleId="R1",
                        message=Message(text="finding"),
                        locations=[
                            Location(
                                physicalLocation=PhysicalLocation(
                                    artifactLocation=ArtifactLocation(uri=uri)
                                )
                            )
                        ],
                    )
                    for uri in uris
                ],
            )
        ]
    )


def _drop_in_output_dir(tmp_path: Path, directory: str, monkeypatch) -> int:
    # The drop's warning names the directory as listed; pytest-xdist cannot send a
    # captured record holding a surrogate, so the logger is replaced.
    from unittest.mock import MagicMock

    from automated_security_helper.utils import scan_output_dirs

    monkeypatch.setattr(scan_output_dirs, "ASH_LOGGER", MagicMock())
    source = tmp_path / directory / "src"
    output = source / directory
    _make(output / "reports" / "ash.sarif")
    _make(source / "app.py")
    context = PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / "converted",
        config=AshConfig(),
    )
    report = _report(f"{directory}/reports/ash.sarif", "app.py")
    return drop_results_in_ash_output_dirs(report, context, scanner_name="scripted")


def _mark_converted(tmp_path: Path, directory: str, monkeypatch) -> int:
    source = tmp_path / directory / "src"
    output = source / directory
    work = output / "converted"
    converted = _make(work / "jupyter" / "nb.py")
    context = PluginContext(
        source_dir=source, output_dir=output, work_dir=work, config=AshConfig()
    )
    return mark_converted_results(_report(converted.as_posix(), "app.py"), context)


@pytest.mark.parametrize(
    "decide",
    [_drop_in_output_dir, _mark_converted],
    ids=["output-dir-drop", "converted-results-mark"],
)
def test_an_output_dir_named_so_gets_the_decision_a_plain_one_gets(
    tmp_path, monkeypatch, decide
):
    plain = decide(tmp_path, PLAIN_DIR, monkeypatch)
    odd = decide(tmp_path, ODD_DIR, monkeypatch)

    assert plain == 1
    assert odd == plain


def test_a_listed_file_set_keeps_the_odd_file_as_it_keeps_the_plain_one(tmp_path):
    report = _report(names.ODD, CONTROL, KEEP)

    report.filter_results_by_files({names.ODD, CONTROL}, tmp_path)

    uris = [
        r.locations[0].physicalLocation.root.artifactLocation.uri
        for r in report.get_all_results()
    ]
    assert uris == [RECORDED, CONTROL]
