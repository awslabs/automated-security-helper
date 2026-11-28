"""Each file of an ``extends`` chain has its old spellings read as the canonical ones.

The loader folds a file's old spellings (``expiration`` for ``expires``) onto
the canonical key before it layers the file over another. So:

* the deprecation is said once per file and spelling, naming the file, however
  many entries use it, and whether or not unknown entry keys are fatal;
* a base that the operator's overlay and a project's own file both extend is a
  file of both chains, and says its line once;
* a key a file writes as the ``-``/``_`` twin of the key its base writes
  (``global-settings``, or ``ignore-paths`` under ``global_settings``) is read as
  that key, so an old spelling under it is said for that file;
* a file that writes both spellings with different values is refused naming
  that file, whichever file of the chain it is;
* a ``patch`` pointer in either spelling reaches the key the merged document
  holds, so a child and its base can each be written in either spelling, and a
  pointer or an op's value in the old spelling is said like any other key;
* a key a later file's ``patch`` writes again is that file's key: a refusal of
  its value names it as the patch spells it, not as the base spelled the key the
  patch wrote over;
* a key that is canonical in another model (a content database staleness
  override's ``expiration``) is left as written;
* a scanner section the scanners segment does not declare is read as the
  config class of a scanner ASH ships whose manifest gives no typed section
  (guarddog's), under the manifest's name or a case variant of it, and any other
  such section is left as written;
* the line names the file as it is, and the sink that shows a resolution
  warning writes a control in the name as its escape, once;
* a value an old-spelling key reads from the environment is recorded at the
  canonical key, where the configuration holds it.

Each of these is pinned below: three entries in two files give two lines, one
naming each file, and ``fail_on_unknown_keys: true`` gives the line too; a base
an overlay and a project both extend gives one line; an entry under a twin key
gives its file one line; a disagreement in a base is refused naming the base; a
pointer in either spelling applies over a base in the other; a key a patch
writes again is refused under the patch's spelling, and with a date loads as it
did; an op's value is folded, its line naming the file, and a disagreement in it
is refused naming the op; guarddog's excluded path gives its file one line under
either key, and a section no shipped manifest names gives none; and an
environment read is recorded at the canonical key.
"""

from pathlib import Path
from typing import Any, Dict, List

import pytest
import yaml

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.exceptions import ASHConfigValidationError
from automated_security_helper.utils.terminal_text import shown_on_one_line

pytestmark = [
    pytest.mark.unit,
    pytest.mark.filterwarnings("ignore::DeprecationWarning"),
]

DEPRECATION = "deprecated spelling of 'expires'"


def _write(path: Path, document: Dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    return path


def _suppression(**expiry: str) -> Dict[str, Any]:
    return {"rule_id": "B101", "path": "src/app.py", "reason": "reviewed", **expiry}


def _deprecation_lines(config: AshConfig) -> List[str]:
    return [line for line in config._resolution_warnings if DEPRECATION in line]


def test_the_deprecation_is_said_once_per_file_naming_the_file(tmp_path: Path) -> None:
    _write(
        tmp_path / "cfg" / "org.yaml",
        {
            "global_settings": {
                "ignore_paths": [
                    {
                        "path": "build/",
                        "reason": "generated",
                        "expiration": "2099-01-01",
                    },
                    {
                        "path": "dist/",
                        "reason": "generated",
                        "expiration": "2099-01-02",
                    },
                ]
            }
        },
    )
    child = _write(
        tmp_path / "cfg" / "repo.yaml",
        {
            "extends": "org.yaml",
            "global_settings": {
                "suppressions": [_suppression(expiration="2099-01-03")],
            },
        },
    )

    config = AshConfig.from_file(child)

    lines = _deprecation_lines(config)
    assert len(lines) == 2, lines
    assert sum("org.yaml" in line for line in lines) == 1, lines
    assert sum("repo.yaml" in line for line in lines) == 1, lines
    # Every entry still reads its expiry.
    assert [p.expires for p in config.global_settings.ignore_paths] == [
        "2099-01-01",
        "2099-01-02",
    ]
    assert config.global_settings.suppressions[0].expires == "2099-01-03"


def test_the_operators_overlay_file_is_folded_too(tmp_path: Path) -> None:
    """The operator's file layered over a project's is a file of its own."""
    from automated_security_helper.config.resolve_config import resolve_config

    project = _write(tmp_path / "repo" / ".ash.yaml", {"fail_on_findings": True})
    operator = _write(
        tmp_path / "operator" / "ops.yaml",
        {"global_settings": {"suppressions": [_suppression(expiration="2099-01-03")]}},
    )

    config = resolve_config(
        config_path=project,
        source_dir=tmp_path / "repo",
        trusted_config_path=operator,
        overlay_config_path=operator,
    )

    lines = _deprecation_lines(config)
    assert len(lines) == 1, lines
    assert "ops.yaml" in lines[0], lines
    assert config.global_settings.suppressions[0].expires == "2099-01-03"


def test_a_base_the_overlay_and_the_project_both_extend_says_its_line_once(
    tmp_path: Path,
) -> None:
    """The operator's overlay and a project's own file can extend one base. A
    project config kept outside its source directory has its bases confined to
    its own directory, as the overlay's are, so here both sit beside the base,
    outside the scanned tree. The base is a file of both chains, and its line is
    said once, as each file's is."""
    from automated_security_helper.config.resolve_config import resolve_config

    _write(
        tmp_path / "ops" / "base.yaml",
        {"global_settings": {"suppressions": [_suppression(expiration="2099-01-03")]}},
    )
    project = _write(
        tmp_path / "ops" / "project.yaml",
        {"extends": "base.yaml", "project_name": "project"},
    )
    operator = _write(
        tmp_path / "ops" / "ops.yaml",
        {"extends": "base.yaml", "fail_on_findings": True},
    )
    (tmp_path / "repo").mkdir()

    config = resolve_config(
        config_path=project,
        source_dir=tmp_path / "repo",
        trusted_config_path=operator,
        overlay_config_path=operator,
    )

    lines = _deprecation_lines(config)
    assert len(lines) == 1, lines
    assert "base.yaml" in lines[0], lines
    # The project's own file was read, under the overlay.
    assert config.project_name == "project"
    assert config.global_settings.suppressions[0].expires == "2099-01-03"


#: A base that writes ``global_settings``, with one ignore path of its own.
_SETTINGS_BASE: Dict[str, Any] = {
    "global_settings": {"ignore_paths": [{"path": "build/", "reason": "generated"}]}
}

#: An extending file's own keys, by the key on the way to an entry that it writes
#: as the ``-``/``_`` twin of the key its base writes: the section itself, or the
#: list under it. The entry writes the old spelling.
_TWIN_CHILDREN: Dict[str, Dict[str, Any]] = {
    "section-twin": {
        "global-settings": {"suppressions": [_suppression(expiration="2099-01-03")]}
    },
    "nested-twin": {
        "global_settings": {
            "ignore-paths": [
                {"path": "dist/", "reason": "generated", "expiration": "2099-01-03"}
            ]
        }
    },
}


@pytest.mark.parametrize("twin", ["section-twin", "nested-twin"])
def test_an_old_spelling_under_a_twin_key_says_the_deprecation_for_its_file(
    tmp_path: Path, twin: str
) -> None:
    """``global-settings`` is the ``-``/``_`` twin of ``global_settings``, and
    ``ignore-paths`` of ``ignore_paths``. The merge reads a key a file writes as
    the twin of its base's key as that key, and so does the fold: the entry under
    it has its old spelling read as the canonical one, and the file gets its own
    line."""
    _write(tmp_path / "cfg" / "org.yaml", _SETTINGS_BASE)
    child = _write(
        tmp_path / "cfg" / "repo.yaml", {"extends": "org.yaml", **_TWIN_CHILDREN[twin]}
    )

    config = AshConfig.from_file(child)

    lines = _deprecation_lines(config)
    assert len(lines) == 1, lines
    assert "repo.yaml" in lines[0], lines
    entries = (
        config.global_settings.suppressions
        if twin == "section-twin"
        else config.global_settings.ignore_paths
    )
    assert [entry.expires for entry in entries] == ["2099-01-03"]


def test_a_disagreement_in_a_base_is_refused_naming_the_base(tmp_path: Path) -> None:
    _write(
        tmp_path / "cfg" / "org.yaml",
        {
            "global_settings": {
                "suppressions": [
                    _suppression(expires="2099-01-01", expiration="2098-01-01")
                ]
            }
        },
    )
    child = _write(
        tmp_path / "cfg" / "repo.yaml",
        {"extends": "org.yaml", "fail_on_findings": False},
    )

    with pytest.raises(ASHConfigValidationError) as refused:
        AshConfig.from_file(child)

    message = str(refused.value)
    assert "org.yaml" in message
    assert "expires" in message
    assert "expiration" in message


def test_a_disagreement_in_a_file_with_no_extends_is_refused_naming_it(
    tmp_path: Path,
) -> None:
    """The control: a lone file was refused, and still is, naming it."""
    config = _write(
        tmp_path / "cfg" / "only.yaml",
        {
            "global_settings": {
                "suppressions": [
                    _suppression(expires="2099-01-01", expiration="2098-01-01")
                ]
            }
        },
    )

    with pytest.raises(ASHConfigValidationError) as refused:
        AshConfig.from_file(config)

    message = str(refused.value)
    assert "only.yaml" in message
    assert "expires" in message
    assert "expiration" in message


def _child_patching(tmp_path: Path, base_entry: Dict[str, Any], ops: List[Any]) -> Path:
    _write(
        tmp_path / "cfg" / "org.yaml",
        {"global_settings": {"suppressions": [base_entry]}},
    )
    return _write(tmp_path / "cfg" / "repo.yaml", {"extends": "org.yaml", "patch": ops})


@pytest.mark.parametrize(
    "base_spelling,pointer_spelling",
    [("expires", "expiration"), ("expiration", "expires")],
    ids=["old-pointer-over-canonical-base", "canonical-pointer-over-old-base"],
)
def test_a_childs_patch_reaches_the_bases_expiry_in_either_spelling(
    tmp_path: Path, base_spelling: str, pointer_spelling: str
) -> None:
    child = _child_patching(
        tmp_path,
        _suppression(**{base_spelling: "2099-01-01"}),
        [
            {
                "op": "replace",
                "path": f"/global_settings/suppressions/0/{pointer_spelling}",
                "value": "2199-12-31",
            }
        ],
    )

    config = AshConfig.from_file(child)

    assert config.global_settings.suppressions[0].expires == "2199-12-31"


def test_a_childs_test_op_reads_the_bases_expiry_in_the_old_spelling(
    tmp_path: Path,
) -> None:
    child = _child_patching(
        tmp_path,
        _suppression(expires="2099-01-01"),
        [
            {
                "op": "test",
                "path": "/global_settings/suppressions/0/expiration",
                "value": "2099-01-01",
            },
            {
                "op": "replace",
                "path": "/global_settings/suppressions/0/reason",
                "value": "re-reviewed",
            },
        ],
    )

    config = AshConfig.from_file(child)

    assert config.global_settings.suppressions[0].reason == "re-reviewed"


def test_a_childs_patch_in_the_bases_own_old_spelling_still_applies(
    tmp_path: Path,
) -> None:
    """The control: both files in the old spelling, as before the fold existed."""
    child = _child_patching(
        tmp_path,
        _suppression(expiration="2099-01-01"),
        [
            {
                "op": "replace",
                "path": "/global_settings/suppressions/0/expiration",
                "value": "2199-12-31",
            }
        ],
    )

    config = AshConfig.from_file(child)

    assert config.global_settings.suppressions[0].expires == "2199-12-31"


def test_a_patch_pointer_in_the_old_spelling_says_the_deprecation_for_its_file(
    tmp_path: Path,
) -> None:
    child = _child_patching(
        tmp_path,
        _suppression(expires="2099-01-01"),
        [
            {
                "op": "replace",
                "path": "/global_settings/suppressions/0/expiration",
                "value": "2199-12-31",
            }
        ],
    )

    config = AshConfig.from_file(child)

    lines = _deprecation_lines(config)
    assert len(lines) == 1, lines
    assert "repo.yaml" in lines[0], lines
    assert config.global_settings.suppressions[0].expires == "2199-12-31"


def _patch_writing_the_expiry(how: str, value: str) -> List[Dict[str, Any]]:
    """A ``patch`` that writes the expiry of the base's first suppression again,
    under the canonical key, with ``value``: ``remove-then-add`` removes the key
    and adds it back, and ``replace`` replaces it."""
    pointer = "/global_settings/suppressions/0/expires"
    if how == "replace":
        return [{"op": "replace", "path": pointer, "value": value}]
    return [
        {"op": "remove", "path": pointer},
        {"op": "add", "path": pointer, "value": value},
    ]


@pytest.mark.parametrize("how", ["remove-then-add", "replace"])
def test_a_key_a_patch_writes_again_is_named_as_the_patch_spells_it(
    tmp_path: Path, how: str
) -> None:
    """The base writes ``expiration``, and the child's ``patch`` writes the key
    again under ``expires`` with a value that is not a date. The value refused is
    the child's, under the key the child wrote, so the location names
    ``expires``, never the base's spelling of a key the patch wrote over."""
    child = _child_patching(
        tmp_path,
        _suppression(expiration="2099-01-01"),
        _patch_writing_the_expiry(how, "not-a-date"),
    )

    with pytest.raises(ASHConfigValidationError) as refused:
        AshConfig.from_file(child)

    message = str(refused.value)
    assert "repo.yaml" in message
    assert "Invalid value at 'global_settings.suppressions[0].expires'" in message
    assert "suppressions[0].expiration" not in message


@pytest.mark.parametrize("how", ["remove-then-add", "replace"])
def test_a_key_a_patch_writes_again_with_a_date_loads_as_it_did(
    tmp_path: Path, how: str
) -> None:
    """The control: only the refusal's wording is the patch's. With a date the
    same chain loads the value the patch wrote, and the base's line is still
    said."""
    child = _child_patching(
        tmp_path,
        _suppression(expiration="2099-01-01"),
        _patch_writing_the_expiry(how, "2199-12-31"),
    )

    config = AshConfig.from_file(child)

    assert config.global_settings.suppressions[0].expires == "2199-12-31"
    lines = _deprecation_lines(config)
    assert len(lines) == 1, lines
    assert "org.yaml" in lines[0], lines


def _added_suppression(**expiry: str) -> Dict[str, Any]:
    """An entry a ``patch`` op adds, at a path no other entry holds."""
    return {"rule_id": "B101", "path": "src/other.py", "reason": "reviewed", **expiry}


def test_a_patch_ops_value_is_folded_saying_the_deprecation_for_its_file(
    tmp_path: Path,
) -> None:
    """The keys inside an op's value are the file's own keys too."""
    child = _child_patching(
        tmp_path,
        _suppression(expires="2099-01-01"),
        [
            {
                "op": "add",
                "path": "/global_settings/suppressions/-",
                "value": _added_suppression(expiration="2099-02-02"),
            }
        ],
    )

    config = AshConfig.from_file(child)

    lines = _deprecation_lines(config)
    assert len(lines) == 1, lines
    assert "repo.yaml" in lines[0], lines
    assert [s.expires for s in config.global_settings.suppressions] == [
        "2099-01-01",
        "2099-02-02",
    ]


def test_a_patch_ops_value_with_disagreeing_spellings_is_refused_naming_the_op(
    tmp_path: Path,
) -> None:
    child = _child_patching(
        tmp_path,
        _suppression(expires="2099-01-01"),
        [
            {
                "op": "add",
                "path": "/global_settings/suppressions/-",
                "value": _added_suppression(
                    expires="2099-02-02", expiration="2098-02-02"
                ),
            }
        ],
    )

    with pytest.raises(ASHConfigValidationError) as refused:
        AshConfig.from_file(child)

    message = str(refused.value)
    assert "repo.yaml" in message
    assert "patch[0]" in message
    assert "expires" in message
    assert "expiration" in message


def test_the_deprecation_is_said_when_unknown_entry_keys_are_fatal(
    tmp_path: Path,
) -> None:
    """``fail_on_unknown_keys: true`` refuses a key the entry does not know. An
    old spelling is a key it knows, and its line is said either way."""
    config = _write(
        tmp_path / "cfg" / "only.yaml",
        {
            "fail_on_unknown_keys": True,
            "global_settings": {
                "suppressions": [_suppression(expiration="2099-01-01")],
            },
        },
    )

    loaded = AshConfig.from_file(config)

    lines = _deprecation_lines(loaded)
    assert len(lines) == 1, lines
    assert "only.yaml" in lines[0], lines
    assert loaded.global_settings.suppressions[0].expires == "2099-01-01"


def test_a_staleness_overrides_expiration_is_its_own_canonical_key(
    tmp_path: Path,
) -> None:
    """``expiration`` is the required, canonical key of this model: left alone."""
    config = _write(
        tmp_path / "cfg" / "only.yaml",
        {
            "content_db_staleness_overrides": [
                {
                    "database": "grype-db",
                    "policy": "warn",
                    "expiration": "2099-01-01",
                    "reason": "upstream paused",
                }
            ]
        },
    )

    loaded = AshConfig.from_file(config)

    assert loaded.content_db_staleness_overrides[0].expiration == "2099-01-01"
    assert _deprecation_lines(loaded) == []


#: An excluded path of a scanner's section, without its expiry.
_EXCLUDED = {"path": "tests/", "reason": "reviewed"}

#: A scanner section no shipped manifest names: a plugin from elsewhere.
_UNSHIPPED_SECTION = "in-house-tool"


def _excluded_paths_document(section: str, **expiry: str) -> Dict[str, Any]:
    """A file whose scanner section ``section`` holds one excluded path, with
    ``expiry``."""
    entry = {**_EXCLUDED, **expiry}
    return {"scanners": {section: {"options": {"excluded_paths": [entry]}}}}


def _held_excluded_paths(config: AshConfig, section: str) -> List[Dict[str, Any]]:
    """The excluded paths of the section ``section``. The scanners segment
    declares no field for it, so it holds the section as the mapping the file
    wrote."""
    return (config.scanners.model_extra or {})[section]["options"]["excluded_paths"]


@pytest.mark.parametrize(
    "section", ["guarddog", "GuardDog"], ids=["manifest-name", "case-variant"]
)
def test_an_excluded_path_in_guarddogs_section_says_the_deprecation_for_its_file(
    tmp_path: Path, section: str
) -> None:
    """guarddog's manifest gives no typed section, so the scanners segment
    declares no field for it. The fold reads the section as the scanner's own
    config class, under the manifest's name or a case variant of it, which the
    loader keeps as the file writes it: the line is said once, naming the file,
    and the excluded path holds its expiry under the canonical key."""
    config = _write(
        tmp_path / "cfg" / "only.yaml",
        _excluded_paths_document(section, expiration="2099-01-01"),
    )

    loaded = AshConfig.from_file(config)

    lines = _deprecation_lines(loaded)
    assert len(lines) == 1, lines
    assert "only.yaml" in lines[0], lines
    assert _held_excluded_paths(loaded, section) == [
        {**_EXCLUDED, "expires": "2099-01-01"}
    ]


def test_an_excluded_path_in_a_section_no_shipped_manifest_names_is_left_as_written(
    tmp_path: Path,
) -> None:
    """The limit of that walk: an undeclared section is read only as the config
    class of a scanner ASH ships whose manifest gives no typed section. A section
    no shipped manifest names, a plugin from elsewhere, is not walked: its old
    spelling is not respelled or said here, that plugin's own model renames it
    (silently from the removal release), and lint does not report it."""
    config = _write(
        tmp_path / "cfg" / "only.yaml",
        _excluded_paths_document(_UNSHIPPED_SECTION, expiration="2099-01-01"),
    )

    loaded = AshConfig.from_file(config)

    assert _deprecation_lines(loaded) == []
    assert _held_excluded_paths(loaded, _UNSHIPPED_SECTION) == [
        {**_EXCLUDED, "expiration": "2099-01-01"}
    ]


def test_a_files_name_with_a_control_in_it_is_shown_once_in_its_line(
    tmp_path: Path,
) -> None:
    """The line names the file as it is, and the sink that shows a resolution
    warning (core/orchestrator.py, through utils/terminal_text.py's
    shown_on_one_line) writes the name's override as its escape. Escaped before
    that, the name would be shown twice, its backslash doubled. A right-to-left
    override is a character every platform's file names may hold."""
    name = "cfg" + chr(0x202E) + "lmay.yaml"
    config = _write(
        tmp_path / name,
        {"global_settings": {"suppressions": [_suppression(expiration="2099-01-01")]}},
    )

    loaded = AshConfig.from_file(config)

    lines = _deprecation_lines(loaded)
    assert len(lines) == 1, lines
    shown = shown_on_one_line(lines[0])
    assert "cfg" + chr(92) + "u202elmay.yaml" in shown, shown
    assert chr(92) * 2 not in shown, shown


def test_an_environment_read_under_the_old_spelling_is_recorded_at_the_canonical_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The file as written, with its environment references, is folded as its
    data is, so the two views pair up: a value the old-spelling key read from
    the environment is recorded where the configuration holds it, and a rewrite
    of the file keeps its reference there."""
    from automated_security_helper.config.config_sources import (
        resolve_config_document,
    )

    monkeypatch.setenv("ASH_TEST_EXPIRY", "2099-01-01")
    config = tmp_path / "cfg" / "only.yaml"
    config.parent.mkdir(parents=True)
    config.write_text(
        "global_settings:\n"
        "  suppressions:\n"
        "    - rule_id: B101\n"
        "      path: src/app.py\n"
        "      reason: reviewed\n"
        "      expiration: ${ASH_TEST_EXPIRY}\n",
        encoding="utf-8",
    )

    document = resolve_config_document(config)

    values = [r for r in document.environment_references if not r.key]
    assert [tuple(str(part) for part in r.path) for r in values] == [
        ("global_settings", "suppressions", "0", "expires")
    ]
    assert "ASH_TEST_EXPIRY" in values[0].written
