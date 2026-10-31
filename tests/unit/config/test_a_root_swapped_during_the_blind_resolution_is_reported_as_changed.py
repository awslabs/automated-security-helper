# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A root swapped while a refused chain is explained is reported as a changed file.

When a chain refuses on something read from the environment, the failure is
rebuilt from a second resolution that reads nothing from it
(``_environment_blind_error``). Two gaps let a root swapped around that second
resolution pass without complaint.

The second resolution was not held to the identity the first one read the root
as: the literal reader took no ``expect``, so the chain walk dropped it, and a
root swapped in between was read as the file now at the name. The reader now
takes ``expect`` and the helper hands it the identity the first resolution held.

A refusal of the second resolution that is a plain ``OSError`` (a
``ConfigFileChangedError`` is one) was swallowed into the generic reason with no
mark, and the generic reason itself carried no mark when the first resolution
had met a changed file. The caller raises the error ``from None``, which drops
what it was raised from, so the fact that a file changed rides on a mark that
holds no path.

Red at the base: ``read_config_file_literally`` and ``_environment_blind_error``
took no ``expect``, the swallowed ``OSError`` left no mark, and the generic reason
was returned unmarked after an incoming changed-file error. The plain failure
controls hold at both ends.
"""

from __future__ import annotations

import errno
from pathlib import Path
from typing import Any

import pytest

from automated_security_helper.config import config_sources
from automated_security_helper.config.config_sources import (
    ConfigFileChangedError,
    _environment_blind_error,
    config_file_changed,
    file_identity,
    identity_to_hold,
    read_config_file_literally,
    resolve_config_document,
)
from automated_security_helper.core.exceptions import ASHConfigSourceError

pytestmark = pytest.mark.unit


def _raised_as_the_caller_raises_it(blind: ASHConfigSourceError):
    with pytest.raises(ASHConfigSourceError) as caught:
        raise blind from None
    assert caught.value.__cause__ is None, "premise: the chain was cut"
    return caught.value


def _a_changed_file_refusal() -> ASHConfigSourceError:
    """A refusal raised from a ``ConfigFileChangedError``, as a first resolution
    that met a swapped file raises it."""
    try:
        try:
            raise ConfigFileChangedError(errno.ESTALE, "changed after it was checked")
        except ConfigFileChangedError as cause:
            raise ASHConfigSourceError("the chain was refused") from cause
    except ASHConfigSourceError as refusal:
        return refusal


def _second_resolution(monkeypatch: pytest.MonkeyPatch, raises: Any = None) -> dict:
    """Stand in for the second resolution: record what it was given, then raise
    ``raises`` (or return)."""
    seen: dict = {}

    def walk(*args: Any, **kwargs: Any) -> Any:
        seen.update(kwargs)
        if raises is not None:
            raise raises

    monkeypatch.setattr(config_sources, "resolve_config_document", walk)
    return seen


def test_the_literal_reader_holds_a_read_to_the_identity_it_is_given(
    tmp_path: Path,
) -> None:
    root = tmp_path / ".ash.yaml"
    root.write_text("project_name: p\n", encoding="utf-8")
    other = tmp_path / "other.yaml"
    other.write_text("project_name: q\n", encoding="utf-8")

    assert read_config_file_literally(root, expect=identity_to_hold(root)) == {
        "project_name": "p"
    }
    assert read_config_file_literally(root) == {"project_name": "p"}
    with pytest.raises(ConfigFileChangedError):
        read_config_file_literally(root, expect=identity_to_hold(other))


def test_a_root_that_changed_during_the_second_resolution_is_a_changed_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _second_resolution(
        monkeypatch,
        raises=ConfigFileChangedError(errno.ESTALE, "changed after it was checked"),
    )

    blind = _environment_blind_error(
        tmp_path / ".ash.yaml", tmp_path, None, ASHConfigSourceError("refused")
    )

    raised = _raised_as_the_caller_raises_it(blind)
    assert config_file_changed(raised)
    # The refusal is the generic reason, which names the config it is about; the
    # fact that a file changed rides on the mark, which holds no path.
    assert "environment references hold" in str(raised), "premise: the generic reason"


def test_a_plain_failure_of_the_second_resolution_stays_a_plain_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control: a stale handle the file system reports is a plain OSError
    with the same errno, and is not taken for a swap."""
    _second_resolution(monkeypatch, raises=OSError(errno.ESTALE, "stale file handle"))

    blind = _environment_blind_error(
        tmp_path / ".ash.yaml", tmp_path, None, ASHConfigSourceError("refused")
    )

    assert not config_file_changed(_raised_as_the_caller_raises_it(blind))


def test_the_generic_reason_keeps_the_fact_that_the_first_resolution_met_a_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The second resolution resolves, so the reason is the generic one; it is
    returned with the mark the incoming refusal carried in its cause chain."""
    _second_resolution(monkeypatch)

    blind = _environment_blind_error(
        tmp_path / ".ash.yaml", tmp_path, None, _a_changed_file_refusal()
    )

    raised = _raised_as_the_caller_raises_it(blind)
    assert "environment references hold" in str(raised), "premise: the generic reason"
    assert config_file_changed(raised)


def test_a_second_refusal_that_names_a_reference_keeps_the_mark_too(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The literal resolution failed at a reference, so its reason is not used and
    the generic one is returned, marked."""
    _second_resolution(
        monkeypatch, raises=ASHConfigSourceError("cannot read ${SOME_BASE}")
    )

    blind = _environment_blind_error(
        tmp_path / ".ash.yaml", tmp_path, None, _a_changed_file_refusal()
    )

    raised = _raised_as_the_caller_raises_it(blind)
    assert "${" not in str(raised), "premise: the generic reason"
    assert config_file_changed(raised)


def test_a_generic_reason_after_a_plain_refusal_carries_no_mark(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control: nothing changed, so the generic reason is not marked."""
    _second_resolution(monkeypatch)

    blind = _environment_blind_error(
        tmp_path / ".ash.yaml", tmp_path, None, ASHConfigSourceError("refused")
    )

    assert not config_file_changed(_raised_as_the_caller_raises_it(blind))


def test_the_second_resolution_is_given_the_identity_the_first_one_held(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen = _second_resolution(monkeypatch)
    identity = (7, 11)

    _environment_blind_error(
        tmp_path / ".ash.yaml",
        tmp_path,
        None,
        ASHConfigSourceError("refused"),
        expect=identity,
    )

    assert seen["expect"] == identity


def test_a_root_swapped_between_the_two_resolutions_is_refused_as_changed(
    tmp_path: Path,
) -> None:
    """Driven through the real literal resolution: the identity handed on is not
    the root's, as when a different file has come to be at the name."""
    root = tmp_path / ".ash.yaml"
    root.write_text("project_name: p\n", encoding="utf-8")
    other = tmp_path / "other.yaml"
    other.write_text("project_name: q\n", encoding="utf-8")

    blind = _environment_blind_error(
        root,
        tmp_path,
        None,
        ASHConfigSourceError("refused"),
        expect=file_identity(other),
    )

    assert config_file_changed(_raised_as_the_caller_raises_it(blind))


def test_an_unswapped_root_is_read_by_the_second_resolution(tmp_path: Path) -> None:
    """The control: handed the root's own identity, the literal resolution reads
    it, and the generic reason is returned unmarked."""
    root = tmp_path / ".ash.yaml"
    root.write_text("project_name: p\n", encoding="utf-8")

    blind = _environment_blind_error(
        root,
        tmp_path,
        None,
        ASHConfigSourceError("refused"),
        expect=identity_to_hold(root),
    )

    assert not config_file_changed(_raised_as_the_caller_raises_it(blind))


@pytest.mark.parametrize("given", [False, True], ids=["taken-at-the-read", "given"])
def test_the_resolution_hands_the_root_identity_it_read_with_to_the_blind_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, given: bool
) -> None:
    monkeypatch.delenv("ASH_U35_UNSET", raising=False)
    (tmp_path / "base.yaml").write_text(
        "global_settings:\n  severity_threshold: ${ASH_U35_UNSET}\n", encoding="utf-8"
    )
    root = tmp_path / ".ash.yaml"
    root.write_text("extends: base.yaml\nproject_name: p\n", encoding="utf-8")
    seen: dict = {}

    def recorder(*args: Any, **kwargs: Any) -> ASHConfigSourceError:
        seen.update(kwargs)
        return ASHConfigSourceError("blind")

    monkeypatch.setattr(config_sources, "_environment_blind_error", recorder)

    with pytest.raises(ASHConfigSourceError):
        if given:
            resolve_config_document(root, expect=identity_to_hold(root))
        else:
            resolve_config_document(root)

    assert seen["expect"] == identity_to_hold(root)
