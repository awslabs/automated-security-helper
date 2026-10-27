"""`config update --set` refuses a value shaped like an environment reference.

`config update` refuses to rewrite a file that reads the environment, so it
must not create one either: a `--set k=${VAR}` would write a live reference
(or, quoted, silently turn the typed reference into literal text). The
refusal names the key only and says to edit the file to add a reference; a
plain value, and a `$` without the reference shape, still set.
"""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app

CONFIG = "project_name: before\n"


def _update(tmp_path, monkeypatch, *sets):
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    path = tmp_path / "ash.yaml"
    path.write_text(CONFIG, encoding="utf-8")
    before = path.read_bytes()
    args = ["config", "update", "--config", str(path)]
    for one in sets:
        args += ["--set", one]
    result = CliRunner().invoke(app, args)
    return path, before, result


@pytest.mark.parametrize(
    "value",
    ["${ASH_REFSHAPE_VAR}", "${ASH_REFSHAPE_VAR} and text", "!ENV ${ASH_REFSHAPE_VAR}"],
    ids=["reference", "reference-prefix", "env-tag"],
)
def test_a_reference_shaped_set_value_is_refused_with_the_key_only(
    tmp_path, monkeypatch, value
):
    path, before, result = _update(tmp_path, monkeypatch, f"project_name={value}")
    flat = " ".join(result.output.split())
    assert result.exit_code != 0, (result.exit_code, flat[-800:])
    assert "project_name" in flat, flat[-800:]
    assert "ASH_REFSHAPE_VAR" not in flat, flat[-800:]
    assert path.read_bytes() == before


def test_a_reference_shaped_string_inside_a_list_value_is_refused(
    tmp_path, monkeypatch
):
    # An ignore_paths entry is an object, so a bare string would be refused by
    # validation anyway; the object shape reaches the walk's mapping and list
    # arms and sets with rc 0 when the check is disabled.
    path, before, result = _update(
        tmp_path,
        monkeypatch,
        'global_settings.ignore_paths=[{"path": "${ASH_REFSHAPE_VAR}", "reason": "r"}]',
    )
    flat = " ".join(result.output.split())
    assert result.exit_code != 0, (result.exit_code, flat[-800:])
    assert "ASH_REFSHAPE_VAR" not in flat, flat[-800:]
    assert path.read_bytes() == before


@pytest.mark.parametrize(
    "value",
    [" ${ASH_REFSHAPE_VAR}", "\t${ASH_REFSHAPE_VAR}", " !ENV ${ASH_REFSHAPE_VAR}"],
    ids=["leading-space", "leading-tab", "spaced-env-tag"],
)
def test_a_reference_behind_whitespace_is_refused(tmp_path, monkeypatch, value):
    """The model strips whitespace (str_strip_whitespace), so a value the
    check reads as plain still loads as a reference lookalike written
    literal; the check matches the stripped text."""
    path, before, result = _update(tmp_path, monkeypatch, f"project_name={value}")
    flat = " ".join(result.output.split())
    assert result.exit_code != 0, (result.exit_code, flat[-800:])
    assert "project_name" in flat, flat[-800:]
    assert "ASH_REFSHAPE_VAR" not in flat, flat[-800:]
    assert path.read_bytes() == before


def test_a_reference_nested_500_deep_is_refused_without_a_crash(tmp_path, monkeypatch):
    """The walk is iterative, so a reference at any depth is refused with the
    key named; a recursing walk crashed with a RecursionError traceback and
    exit 1 instead, and never named the key."""
    value = "[" * 500 + '"${ASH_REFSHAPE_VAR}"' + "]" * 500
    path, before, result = _update(
        tmp_path, monkeypatch, f"global_settings.ignore_paths={value}"
    )
    flat = " ".join(result.output.split())
    assert not isinstance(result.exception, RecursionError), "the walk recursed"
    assert result.exit_code != 0, (result.exit_code, flat[-800:])
    assert "ignore_paths" in flat, flat[-800:]
    assert "ASH_REFSHAPE_VAR" not in flat, flat[-800:]
    # The shape refusal's own wording, not the apply's: a deep list that fails
    # validation also exits non-zero naming ignore_paths, so without this line
    # the cell cannot tell which check answered.
    assert "shaped like an environment reference" in flat, flat[-800:]
    assert path.read_bytes() == before


def test_a_plain_list_nested_500_deep_is_answered_without_a_crash(
    tmp_path, monkeypatch
):
    """A deep value with no reference passes the check and is answered by the
    apply's own refusal; the recursing walk crashed before the apply ran."""
    value = "[" * 500 + "1" + "]" * 500
    path, before, result = _update(
        tmp_path, monkeypatch, f"global_settings.ignore_paths={value}"
    )
    assert not isinstance(result.exception, RecursionError), "the walk recursed"
    assert path.read_bytes() == before


def test_a_plain_value_nested_5000_deep_is_answered_by_the_apply(tmp_path, monkeypatch):
    """A deeper value with no reference: the shape check's iterative walk
    passes it, validation refuses it, and describing that refusal walks the
    refused input to redact it. That walk has to be iterative too; recursing,
    it crashed with a RecursionError traceback instead of the apply's one-line
    refusal, and the cell above never reached it because 500 frames still fit
    under the interpreter's limit."""
    value = "[" * 5000 + "1" + "]" * 5000
    path, before, result = _update(
        tmp_path, monkeypatch, f"global_settings.ignore_paths={value}"
    )
    flat = " ".join(result.output.split())
    assert not isinstance(result.exception, RecursionError), "the redaction recursed"
    assert result.exit_code != 0, (result.exit_code, flat[-800:])
    assert path.read_bytes() == before


def test_a_reference_shaped_key_segment_is_refused(tmp_path, monkeypatch):
    """A reference-shaped key segment would be written as a quoted literal
    key the load tolerates and ignores; it is refused like a value. The
    segment is the caller's own typed text (the load never resolved it), so
    the refusal may name the key path as typed."""
    path, before, result = _update(
        tmp_path, monkeypatch, "reporters.${ASH_REFSHAPE_VAR}.enabled=true"
    )
    flat = " ".join(result.output.split())
    assert result.exit_code != 0, (result.exit_code, flat[-800:])
    assert path.read_bytes() == before


@pytest.mark.parametrize(
    "value, written",
    [("plain-name", "plain-name"), ("costs $5", "costs $5")],
    ids=["plain", "dollar-not-a-reference"],
)
def test_control_a_plain_value_still_sets(tmp_path, monkeypatch, value, written):
    from automated_security_helper.config.config_sources import load_config_document

    path, _, result = _update(tmp_path, monkeypatch, f"project_name={value}")
    assert result.exit_code == 0, (result.exit_code, result.output[-800:])
    assert load_config_document(path)["project_name"] == written
